from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import datetime
import dateparser
import uuid

from ..database import db_assets, db_nodes
from .scanner import scan_target
from .risk_engine import calculate_advanced_risk
from .report_generator import generate_pdf_report
from .chatbot import send_email, summarize_report

# Initialize scheduler
scheduler = BackgroundScheduler()

def start_scheduler():
    if not scheduler.running:
        scheduler.start()
        print("Background Scheduler Started.")

def _execute_scheduled_scan(domain: str, email: str = "admin@quantumshield.local"):
    """
    The actual job that runs when the schedule triggers.
    Runs the scan, generates the report, and emails it.
    """
    try:
        print(f"Executing scheduled scan for {domain}...")
        
        # 1. Run scan
        scan_data = scan_target(domain)
        
        # 2. Compute risk grading
        tls_versions = scan_data.get("tls_versions_list") or [scan_data.get("tls_version", "TLS 1.2")]
        risk_data = calculate_advanced_risk(
            tls_versions,
            scan_data["algorithm"],
            scan_data["key_size"],
            scan_data["days_to_expiry"],
            scan_data.get("vulnerabilities", []),
            scan_data.get("hosting", {"type": "internal"}),
        )
        
        # 3. Create or Update Asset Record
        asset_id = str(uuid.uuid4())
        new_asset = {
            "id": asset_id,
            "type": "Domain",
            "name": domain,
            "detection_date": datetime.datetime.now().isoformat(),
            "status": "active",
            "vendor": "Scanned Endpoint",
            "region": "Dynamic",
            "ip_address": scan_data.get("ipv4", "Resolving..."),
            "risk": risk_data,
            "scan_result": scan_data,
            "vulnerabilities": scan_data.get("vulnerabilities", []),
            "hosting": scan_data.get("hosting", {"provider": "Unknown", "type": "internal"}),
            "mobile_apps": scan_data.get("mobile_info", {}).get("apps", []),
            "subdomains": scan_data.get("subdomains_info", {}).get("subdomains", []),
            "is_active": True,
            "metadata": {"source": "scheduled_scan"}
        }
        db_assets[asset_id] = new_asset
        db_nodes.append({"id": domain, "type": "Domain", "risk": risk_data["risk_level"]})

        # 4. Generate Report Data
        all_assets = list(db_assets.values())
        vulnerable_assets = [a for a in all_assets if a.get("risk", {}).get("risk_level") in ["High", "Medium"]]
        
        report_data = {
            "assets": all_assets,
            "vulnerable_assets": vulnerable_assets,
            "risk_score": 85,
            "overall_risk": risk_data["risk_level"],
            "recommendations": ["Upgrade RSA-1024 to NIST-approved PQC algorithms", "Renew expiring certificates"]
        }
        
        # 5. Generate AI Summary & PDF
        report_data["executive_summary"] = summarize_report(report_data)
        pdf_bytes = generate_pdf_report(report_data)
        
        # 6. Send Email
        subject = f"Scheduled Quantum Security Report – Risk Level: {risk_data['risk_level']}"
        body = f"Hello,\n\nYour scheduled cryptographic scan for {domain} has completed.\n\nSummary:\n{report_data['executive_summary']}\n\nPlease find the detailed PDF attached.\n\nRegards,\nPrecise Sentinel AI"
        send_email(email, subject, body, [{"filename": "Scheduled_Scan_Report.pdf", "bytes": pdf_bytes}])
        
        print(f"Scheduled scan completed for {domain}. Email sent to {email}.")
    except Exception as e:
        print(f"Scheduled scan error: {e}")


def schedule_scan_job(
    frequency: str,
    time_str: str,
    domain: str = "auto_discovery",
    email: str = "admin@quantumshield.local",
    day_of_week: str = "mon",
    day_of_month: int = 1,
):
    """
    Parses natural language frequency and time to schedule a cron job.
    """
    # Parse time "6 PM" -> hour 18, min 0
    parsed_time = dateparser.parse(time_str)
    hour = parsed_time.hour if parsed_time else 0
    minute = parsed_time.minute if parsed_time else 0
    
    normalized_frequency = (frequency or "daily").lower()
    if normalized_frequency == "daily":
        trigger = CronTrigger(hour=hour, minute=minute)
    elif normalized_frequency == "weekly":
        trigger = CronTrigger(day_of_week=(day_of_week or "mon"), hour=hour, minute=minute)
    elif normalized_frequency == "monthly":
        normalized_day = max(1, min(28, int(day_of_month or 1)))
        trigger = CronTrigger(day=normalized_day, hour=hour, minute=minute)
    elif normalized_frequency == "hourly":
        trigger = CronTrigger(minute=minute)
    else:
        trigger = CronTrigger(hour=hour, minute=minute)
        
    job = scheduler.add_job(
        _execute_scheduled_scan, 
        trigger=trigger, 
        args=[domain, email], 
        replace_existing=False
    )
    
    next_run_time = getattr(job, "next_run_time", None)

    return {
        "job_id": job.id,
        "next_run_time": str(next_run_time) if next_run_time else "pending",
        "domain": domain,
        "frequency": normalized_frequency,
        "time": f"{hour:02d}:{minute:02d}",
        "day_of_week": day_of_week,
        "day_of_month": day_of_month,
    }
