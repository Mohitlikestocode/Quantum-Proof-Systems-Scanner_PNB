from fastapi import FastAPI, HTTPException, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Literal
import asyncio
import datetime
import uuid
from dotenv import load_dotenv

# Load environment variables (SMTP_EMAIL, SMTP_PASSWORD, GEMINI_API_KEY)
load_dotenv()

# Import models and DB
from .models import Asset, ScanResult, RiskScore, ChatCommand
from .database import db_assets, db_jobs, db_nodes, db_edges, seed_database

# Import Engines
from .engines.scanner import scan_target
from .engines.risk_engine import calculate_advanced_risk
from .engines.cbom_generator import generate_cbom
from .engines.chatbot import process_chat_message, summarize_report, send_email
from .engines.scheduler import start_scheduler, schedule_scan_job
from .engines.report_generator import generate_pdf_report

def get_all_assets_list():
    return list(db_assets.values())


def _normalize_domain(domain: str) -> str:
    return (domain or "").strip().lower().replace("http://", "").replace("https://", "").split("/")[0]


def _parse_iso_datetime(value: str) -> datetime.datetime:
    try:
        return datetime.datetime.fromisoformat(value)
    except Exception:
        return datetime.datetime.min


def _get_assets_for_domain(domain: str) -> List[dict]:
    normalized = _normalize_domain(domain)
    matches = [
        asset for asset in get_all_assets_list()
        if _normalize_domain(str(asset.get("name", ""))) == normalized
    ]
    return sorted(matches, key=lambda item: _parse_iso_datetime(item.get("detection_date", "")), reverse=True)


def _build_mobile_rows_from_assets(assets: List[dict]) -> List[dict]:
    rows: List[dict] = []
    for asset in assets:
        apps = asset.get("mobile_apps") or asset.get("scan_result", {}).get("mobile_info", {}).get("apps", [])
        if apps:
            rows.append({"domain": asset.get("name"), "apps": apps})
    return rows


app = FastAPI(title="Quantum-Proof Systems Scanner API")

# Setup CORS for Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For hackathon demo
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    seed_database()
    start_scheduler()

# --- MODULE 1 & 6: ASSET MANAGEMENT ---
@app.get("/api/assets", response_model=List[Asset])
def get_assets(status: Optional[str] = None, type: Optional[str] = None):
    """Retrieve all assets with optional filtering support."""
    assets = list(db_assets.values())
    
    if status and status.lower() != "all":
        assets = [a for a in assets if a["status"] == status.lower()]
    if type and type.lower() != "asset type":
        assets = [a for a in assets if a["type"] == type]
        
    return assets

@app.get("/api/vulnerable-assets", response_model=List[Asset])
def get_vulnerable_assets():
    """Returns only assets classified as High or Medium risk."""
    return [a for a in db_assets.values() if a.get("risk", {}).get("risk_level") in ["High", "Medium"]]

# --- MODULE 2 & 3: SCANNER & RISK ENGINE ---
from pydantic import BaseModel

class ScanRequest(BaseModel):
    domain: str
    mode: Optional[str] = "Full Deep Scan"


class ScheduleRequest(BaseModel):
    domain: str
    email: str
    frequency: Literal["daily", "weekly", "monthly"]
    time: str
    day_of_week: Optional[str] = None
    day_of_month: Optional[int] = None

from fastapi import Header
from .engines.risk_engine import calculate_advanced_risk

@app.post("/api/scan")
def run_scan(request: ScanRequest, background_tasks: BackgroundTasks, x_user_role: Optional[str] = Header(None)):
    """Executes the cryptographic scanner on a domain and computes advanced quantum risk."""
    domain = request.domain
    
    # 1. Run full discovery scan
    scan_data = scan_target(domain, mode=request.mode or "Full Deep Scan")
    
    # Normalize scan fields to avoid runtime failures when handshake fails/inactive targets
    normalized_tls_versions = scan_data.get("tls_versions_list") or []
    if not normalized_tls_versions:
        main_domain_payload = scan_data.get("subdomains_discovery", {}).get("main_domain", {})
        normalized_tls_versions = main_domain_payload.get("tls_versions", [])
    if not normalized_tls_versions:
        normalized_tls_versions = ["TLS 1.2"]

    normalized_algorithm = scan_data.get("algorithm") or "RSA"
    normalized_key_size = scan_data.get("key_size")
    if not isinstance(normalized_key_size, int):
        normalized_key_size = 2048

    normalized_days_to_expiry = scan_data.get("days_to_expiry")
    if not isinstance(normalized_days_to_expiry, int):
        normalized_days_to_expiry = 0

    # 2. Compute advanced risk grading
    risk_data = calculate_advanced_risk(
        normalized_tls_versions,
        normalized_algorithm,
        normalized_key_size,
        normalized_days_to_expiry,
        scan_data.get("vulnerabilities", []),
        scan_data.get("hosting", {"type": "internal"}),
        pqc_kem_detected=scan_data.get("pqc_kem_detected", False),
        pqc_status=scan_data.get("pqc_status", "None"),
    )
    
    # 3. Create or Update Asset Record
    asset_id = str(uuid.uuid4())
    new_asset = {
        "id": asset_id,
        "type": "Domain",
        "name": domain,
        "detection_date": datetime.datetime.now().isoformat(),
        "status": "active",
        "vendor": scan_data.get("hosting", {}).get("provider", "Unknown"),
        "region": "Dynamic",
        "ip_address": scan_data["ipv4"],
        "risk": risk_data,
        "scan_result": {
            **scan_data,
            "tls_version": scan_data.get("tls_version") or "Unknown",
            "tls_versions_list": scan_data.get("tls_versions_list") or [],
            "cipher_suite": scan_data.get("cipher_suite") or "Unknown",
            "key_size": scan_data.get("key_size"),
            "certificate_issuer": scan_data.get("certificate_issuer") or "Unavailable",
            "expiry_date": scan_data.get("expiry_date"),
            "algorithm": scan_data.get("algorithm") or "Unavailable",
            "days_to_expiry": scan_data.get("days_to_expiry"),
            "certificate_signature_oid": scan_data.get("certificate_signature_oid"),
            "certificate_signature_algorithm": scan_data.get("certificate_signature_algorithm"),
            "pqc_kem_detected": scan_data.get("pqc_kem_detected", False),
            "pqc_kem_algorithm": scan_data.get("pqc_kem_algorithm"),
            "pqc_kem_group_id": scan_data.get("pqc_kem_group_id"),
            "pqc_signature_detected": scan_data.get("pqc_signature_detected", False),
            "pqc_signature_algorithm": scan_data.get("pqc_signature_algorithm"),
            "pqc_hybrid": scan_data.get("pqc_hybrid", False),
            "pqc_status": scan_data.get("pqc_status", "None"),
            "pqc_detection_notes": scan_data.get("pqc_detection_notes", []),
            "ipv4": scan_data.get("ipv4") or "0.0.0.0",
            "ipv6": scan_data.get("ipv6") or "::",
            "risk_input": {
                "tls_versions": normalized_tls_versions,
                "algorithm": normalized_algorithm,
                "key_size": normalized_key_size,
                "days_to_expiry": normalized_days_to_expiry,
            },
        },
        "vulnerabilities": scan_data.get("vulnerabilities", []),
        "hosting": scan_data.get("hosting", {"provider": "Unknown", "type": "internal"}),
        "mobile_apps": scan_data.get("mobile_info", {}).get("apps", []),
        "subdomains": scan_data.get("subdomains_info", {}).get("subdomains", []),
        "is_active": True,
        "metadata": {"source": "advanced_scan", "mode": request.mode, "scanned_by_role": x_user_role}
    }
    
    db_assets[asset_id] = new_asset
    
    # Also add mock node for network graph
    db_nodes.append({"id": domain, "type": "Domain", "risk": risk_data["risk_level"]})
    
    return new_asset


@app.post("/api/schedule")
def schedule_scan(request: ScheduleRequest):
    """Create a recurring scan job from the Scanner scheduling form."""
    day_of_week = (request.day_of_week or "mon").lower()[:3]
    day_of_month = request.day_of_month if request.day_of_month is not None else 1

    if request.frequency == "weekly":
        valid_days = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
        if day_of_week not in valid_days:
            raise HTTPException(status_code=400, detail="Invalid day_of_week. Use mon-sun.")

    if request.frequency == "monthly" and (day_of_month < 1 or day_of_month > 28):
        raise HTTPException(status_code=400, detail="day_of_month must be between 1 and 28.")

    try:
        result = schedule_scan_job(
            frequency=request.frequency,
            time_str=request.time,
            domain=request.domain,
            email=request.email,
            day_of_week=day_of_week,
            day_of_month=day_of_month,
        )
        return {"success": True, "message": "Scan scheduled successfully.", **result}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

# --- NEW FULL ASSET DISCOVERY ENDPOINT ---
@app.get("/api/discover")
def run_discovery(domain: str):
    """Module 1: Full scan means domain + subdomains"""
    from .engines.scanner import discover_subdomains
    return discover_subdomains(domain)

# --- MODULE 4: CBOM GENERATOR ---
@app.get("/api/cbom")
def get_all_cboms():
    """Generates the Cryptographic Bill of Materials for all confirmed assets."""
    return [generate_cbom(asset) for asset in db_assets.values() if asset.get("scan_result")]

# --- MODULE 5: DASHBOARD METRICS ---
@app.get("/api/risk")
def get_dashboard_metrics():
    """Aggregates data for the dashboard visualizations including expiring certs."""
    assets = list(db_assets.values())
    total_assets = len(assets)
    
    servers = sum(1 for a in assets if "Hardware" in a["type"] or "SERVER" in str(a.get("metadata", "")).upper())
    apis = sum(1 for a in assets if "Software" in a["type"] or "API" in str(a.get("metadata", "")).upper())
    
    high_risk_assets = [a for a in assets if a.get("risk", {}).get("risk_level") == "High"]
    
    # Expiring within 30 days or already expired
    expiring_certs = [a for a in assets if a.get("scan_result", {}).get("days_to_expiry", 999) < 30]

    pqc_ready_count = sum(1 for a in assets if str(a.get("risk", {}).get("label", "")).upper() == "PQC READY")
    pqc_readiness_pct = int((pqc_ready_count / total_assets) * 100) if total_assets > 0 else 0

    # Heatmap data generation
    heatmap_data = []
    for a in assets:
        scan = a.get("scan_result", {})
        risk = a.get("risk", {}).get("risk_level", "Low")
        heatmap_data.append({
            "asset_name": a["name"],
            "tls_version": scan.get("tls_version", "Unknown"),
            "key_size": scan.get("key_size", "Unknown"),
            "algorithm": scan.get("algorithm", "Unknown"),
            "risk": risk
        })
    
    return {
         "summary": {
            "total_assets": total_assets,
            "servers": servers,
            "apis": apis,
            "high_risk": len(high_risk_assets),
            "medium_risk": sum(1 for a in assets if a.get("risk", {}).get("risk_level") == "Medium"),
            "low_risk": sum(1 for a in assets if a.get("risk", {}).get("risk_level") == "Low"),
            "expiring_certs": len(expiring_certs),
            "pqc_readiness_pct": pqc_readiness_pct
        },
        "high_risk_assets": high_risk_assets,
        "expiring_list": expiring_certs,
        "heatmap": heatmap_data
    }

# --- MODULE 7: NETWORK GRAPH API ---
@app.get("/api/graph")
def get_graph():
    """Returns nodes and edges for rendering the interactive network map."""
    return {
        "nodes": db_nodes,
        "edges": db_edges
    }

# Keeping legacy endpoint just in case
@app.get("/api/network-graph")
def get_network_graph():
    return get_graph()

# --- MODULE: REPORTING ---
@app.get("/api/report")
def generate_report():
    assets = list(db_assets.values())
    high_risk = sum(1 for a in assets if a.get("risk", {}).get("risk_level") == "High")
    total = len(assets)
    
    if total == 0:
        return {"summary": "No assets discovered.", "score": 0, "risk": "Unknown", "recommendations": []}
        
    pqc_ready_pct = int(((total - high_risk) / total) * 100)
    overall_risk = "High" if high_risk > (total * 0.3) else "Moderate" if high_risk > 0 else "Low"
    
    return {
        "summary": f"System is practically {pqc_ready_pct}% quantum-safe. {high_risk} assets use legacy cryptography. Immediate upgrade recommended for High Risk nodes.",
        "score": pqc_ready_pct,
        "risk": overall_risk,
        "recommendations": [
            "Upgrade outdated TLS to 1.3 across all perimeter gateways.",
            "Replace RSA signatures with PQC algorithms like Kyber.",
            "Renew certificates expiring within 30 days."
        ]
    }

from fastapi import Query

VALID_ROLES = {"Super Admin", "Admin", "User"}

def resolve_role(x_user_role_header: Optional[str], x_user_role_query: Optional[str]) -> str:
    role = (x_user_role_header or x_user_role_query or "User").strip()
    if role not in VALID_ROLES:
        return "User"
    return role

def require_super_admin(role: str):
    if role != "Super Admin":
        raise HTTPException(status_code=403, detail="Only Super Admins can access this report.")

def require_admin_or_super(role: str):
    if role == "User":
        raise HTTPException(status_code=403, detail="Users can view JSON reports but cannot export PDFs.")

@app.get("/api/reports/download")
def download_pdf_report(x_user_role: Optional[str] = Query(None), x_user_role_header: Optional[str] = Header(None)):
    """Generates and downloads a robust PDF report of the current infrastructure."""
    role = resolve_role(x_user_role_header, x_user_role)
    require_super_admin(role)
    risk_data = get_dashboard_metrics()
    all_assets = get_all_assets_list()
    vuln_assets = [a for a in all_assets if a.get("risk", {}).get("risk_level") in ["High", "Medium", "Critical"]]
    
    overall_risk = "High" if risk_data["summary"]["high_risk"] > 0 else "Low"
    
    pdf_bytes = generate_pdf_report({
        "executive_summary": f"System is practically {risk_data['summary']['pqc_readiness_pct']}% quantum-safe. {risk_data['summary']['high_risk']} assets use legacy cryptography. Immediate upgrade recommended for High Risk nodes.",
        "risk_score": risk_data["summary"]["pqc_readiness_pct"],
        "overall_risk": overall_risk,
        "assets": all_assets,
        "vulnerable_assets": vuln_assets,
        "recommendations": [
            "Upgrade outdated TLS to 1.3 across all perimeter gateways.",
            "Replace RSA signatures with PQC algorithms like Kyber.",
            "Renew certificates expiring within 30 days."
        ]
    })
    
    import datetime
    date_prefix = datetime.datetime.now().strftime('%Y_%m_%d')
    pdf_name = f'{date_prefix}-CyberRiot_Report.pdf'
    
    return Response(
        content=pdf_bytes, 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename={pdf_name}"}
    )

@app.get("/api/reports/vulnerable-download")
def download_vulnerable_pdf_report(x_user_role: Optional[str] = Query(None), x_user_role_header: Optional[str] = Header(None)):
    """Generates and downloads a PDF report containing ONLY vulnerable assets."""
    role = resolve_role(x_user_role_header, x_user_role)
    require_super_admin(role)
    risk_data = get_dashboard_metrics()
    all_assets = get_all_assets_list()
    vuln_assets = [a for a in all_assets if a.get("risk", {}).get("risk_level") in ["High", "Medium", "Critical"]]
    
    overall_risk = "High" if risk_data["summary"]["high_risk"] > 0 else "Low"
    
    pdf_bytes = generate_pdf_report({
        "report_title": "Critical Vulnerability Disclosures",
        "theme_color": "#dc2626",
        "secondary_theme_color": "#991b1b",
        "executive_summary": f"This report focuses exclusively on vulnerable assets. We identified {len(vuln_assets)} assets requiring immediate remediation due to legacy cryptography or impending certificate expiration.",
        "risk_score": risk_data["summary"]["pqc_readiness_pct"],
        "overall_risk": overall_risk,
        "assets": vuln_assets, 
        "vulnerable_assets": vuln_assets,
        "recommendations": [
            "Upgrade outdated TLS to 1.3 across all perimeter gateways.",
            "Replace RSA signatures with PQC algorithms like Kyber.",
            "Renew certificates expiring within 30 days."
        ]
    })
    
    import datetime
    date_prefix = datetime.datetime.now().strftime('%Y_%m_%d')
    pdf_name = f'{date_prefix}-Vulnerable_Assets_Report.pdf'
    
    return Response(
        content=pdf_bytes, 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename={pdf_name}"}
    )

# --- MODULE 11: GOVERNANCE & ACCESS CONTROL ---
class CreateUserRequest(BaseModel):
    username: str
    target_role: str
    name: str
    password: Optional[str] = None

from .database import db_users

@app.post("/api/users/create")
def create_user(request: CreateUserRequest, x_user_role: Optional[str] = Header(None)):
    """Creates a user. Honors RBAC constraints."""
    if not x_user_role:
        raise HTTPException(status_code=401, detail="Unauthorized")
        
    if request.target_role == "Super Admin" and x_user_role != "Super Admin":
        raise HTTPException(status_code=403, detail="Admin cannot create Super Admin.")
        
    if x_user_role == "User":
        raise HTTPException(status_code=403, detail="Normal users cannot create accounts.")
        
    user_id = str(uuid.uuid4())
    db_users[user_id] = {
        "username": request.username,
        "role": request.target_role,
        "name": request.name,
        "password": request.password or "User@123"
    }
    return {"message": f"User {request.name} created successfully with role {request.target_role}"}

@app.get("/api/users")
def list_users(x_user_role: Optional[str] = Header(None)):
    """Review User Access (Governance)."""
    if x_user_role == "User":
        raise HTTPException(status_code=403, detail="Governance review requires Admin+")
    return [
        {"username": user.get("username"), "role": user.get("role"), "name": user.get("name")}
        for user in db_users.values()
    ]

@app.get("/api/reports/asset-discovery")
def report_asset_discovery():
    all_assets = get_all_assets_list()
    rows = []
    active_domains = 0
    inactive_domains = 0

    for a in all_assets:
        scan_result = a.get("scan_result", {}) or {}
        subdomains = a.get("subdomains", [])
        sub_info = scan_result.get("subdomains_info", {}) if isinstance(scan_result, dict) else {}
        is_active = bool(a.get("is_active", True) and a.get("status", "active") != "inactive")

        if is_active:
            active_domains += 1
        else:
            inactive_domains += 1

        rows.append({
            "domain": a["name"],
            "asset_type": a.get("type"),
            "vendor": a.get("vendor"),
            "status": "active" if is_active else "inactive",
            "subdomains_count": len(subdomains),
            "active_subdomains": sub_info.get("active_assets", 0),
            "inactive_subdomains": sub_info.get("inactive_assets", 0),
            "subdomains": subdomains
        })

    return {
        "report_type": "Asset Discovery",
        "summary": {
            "total_domains": len(rows),
            "active_domains": active_domains,
            "inactive_domains": inactive_domains
        },
        "assets": rows
    }

@app.get("/api/reports/subdomain-risk")
def report_subdomain_risk():
    all_assets = get_all_assets_list()
    results = []
    classification = {"pqc_ready": 0, "standard": 0, "critical": 0}

    for a in all_assets:
        scan_result = a.get("scan_result", {}) or {}
        detailed_subs = scan_result.get("all_subdomains_detailed", []) if isinstance(scan_result, dict) else []

        if detailed_subs:
            for sub in detailed_subs:
                days = sub.get("days_to_expiry")
                if isinstance(days, int) and days > 180:
                    bucket = "pqc_ready"
                elif isinstance(days, int) and days > 90:
                    bucket = "standard"
                else:
                    bucket = "critical"
                classification[bucket] += 1

                results.append({
                    "subdomain": sub.get("subdomain"),
                    "domain": a.get("name"),
                    "status": sub.get("status", "unknown"),
                    "ssl_rating": sub.get("ssl_rating", "N/A"),
                    "days_to_expiry": sub.get("days_to_expiry"),
                    "bucket": bucket,
                    "parent_risk": a.get("risk", {})
                })
        else:
            # Fallback for seeded/static assets that only contain subdomain names
            parent_bucket = "critical"
            parent_risk_level = str(a.get("risk", {}).get("risk_level", "")).lower()
            if parent_risk_level == "low":
                parent_bucket = "pqc_ready"
            elif parent_risk_level == "medium":
                parent_bucket = "standard"

            for sub in a.get("subdomains", []):
                classification[parent_bucket] += 1
                results.append({
                    "subdomain": sub,
                    "domain": a.get("name"),
                    "status": "unknown",
                    "ssl_rating": "N/A",
                    "days_to_expiry": None,
                    "bucket": parent_bucket,
                    "parent_risk": a.get("risk", {})
                })

    return {
        "report_type": "Subdomain Risk",
        "summary": {
            "total_subdomains": len(results),
            "pqc_ready": classification["pqc_ready"],
            "standard": classification["standard"],
            "critical": classification["critical"]
        },
        "data": results
    }

@app.get("/api/reports/vulnerability")
def report_vulnerabilities():
    all_assets = get_all_assets_list()
    results = []
    high_count = 0
    third_party_count = 0

    for a in all_assets:
        if a.get("vulnerabilities"):
            hosting = a.get("hosting") or {}
            vulns = a.get("vulnerabilities", [])
            if any(v.get("severity") == "High" for v in vulns):
                high_count += 1
            if hosting.get("type") == "third_party":
                third_party_count += 1

            results.append({
                "domain": a["name"],
                "vulnerabilities": vulns,
                "vulnerability_count": len(vulns),
                "hosting": hosting,
                "is_third_party": hosting.get("type") == "third_party"
            })

    return {
        "report_type": "Vulnerabilities",
        "summary": {
            "vulnerable_domains": len(results),
            "high_severity_domains": high_count,
            "third_party_hosted": third_party_count
        },
        "data": results
    }

@app.get("/api/reports/mobile-app")
def report_mobile_app():
    all_assets = get_all_assets_list()
    results = []
    android_count = 0
    ios_count = 0

    for a in all_assets:
        if a.get("mobile_apps"):
            apps = a["mobile_apps"]
            android_count += sum(1 for app in apps if app.get("platform") == "android")
            ios_count += sum(1 for app in apps if app.get("platform") == "ios")
            results.append({"domain": a["name"], "apps": apps, "apps_count": len(apps)})

    return {
        "report_type": "Mobile Apps",
        "summary": {
            "domains_with_mobile_apps": len(results),
            "total_apps": android_count + ios_count,
            "android_apps": android_count,
            "ios_apps": ios_count
        },
        "data": results
    }

@app.get("/api/reports/overview")
def report_overview():
    """Unified report payload for the Reports dashboard."""
    asset_discovery = report_asset_discovery()
    subdomain_risk = report_subdomain_risk()
    vulnerability = report_vulnerabilities()
    mobile_app = report_mobile_app()

    return {
        "report_type": "Reports Overview",
        "generated_at": datetime.datetime.now().isoformat(),
        "asset_discovery": asset_discovery,
        "subdomain_risk": subdomain_risk,
        "vulnerability": vulnerability,
        "mobile_app": mobile_app
    }

@app.get("/api/reports/website")
def report_website(domain: str):
    """Return a single website-specific report for the latest matching scan."""
    all_assets = get_all_assets_list()
    matching_assets = [a for a in all_assets if str(a.get("name", "")).lower() == domain.lower()]

    if not matching_assets:
        raise HTTPException(status_code=404, detail="No scanned website found for the requested domain.")

    asset = matching_assets[-1]
    scan = asset.get("scan_result", {}) or {}
    subdomains = scan.get("all_subdomains_detailed", []) if isinstance(scan, dict) else []
    active_subdomains = [sub for sub in subdomains if sub.get("status") == "active"]
    inactive_subdomains = [sub for sub in subdomains if sub.get("status") == "inactive"]

    return {
        "report_type": "Website Report",
        "domain": asset.get("name"),
        "summary": {
            "risk_level": asset.get("risk", {}).get("risk_level", "Unknown"),
            "risk_score": asset.get("risk", {}).get("score", 0),
            "tls_version": scan.get("tls_version", "Unknown"),
            "algorithm": scan.get("algorithm", "Unknown"),
            "key_size": scan.get("key_size", 0),
            "subdomains_total": len(subdomains),
            "subdomains_active": len(active_subdomains),
            "subdomains_inactive": len(inactive_subdomains)
        },
        "website": asset,
        "subdomains": subdomains,
        "active_subdomains": active_subdomains,
        "inactive_subdomains": inactive_subdomains
    }

@app.get("/api/reports/website/download")
def download_website_report(domain: str, x_user_role: Optional[str] = Query(None), x_user_role_header: Optional[str] = Header(None)):
    """Download a PDF report for a single scanned website/domain."""
    role = resolve_role(x_user_role_header, x_user_role)
    require_admin_or_super(role)

    pdf_bytes = build_website_report_pdf(domain)

    date_prefix = datetime.datetime.now().strftime('%Y_%m_%d')
    pdf_name = f'{date_prefix}-{domain}-Website_Report.pdf'
    return _pdf_response(pdf_bytes, pdf_name)

def build_website_report_pdf(domain: str) -> bytes:
    payload = report_website(domain)
    asset = payload["website"]
    scan = asset.get("scan_result", {}) or {}
    mobile_apps = asset.get("mobile_apps") or scan.get("mobile_info", {}).get("apps", [])
    vulnerability_scan = scan.get("vulnerability_scan", {}) or {}
    top_findings = vulnerability_scan.get("top_findings", [])
    top_findings_text = ", ".join(
        f"{f.get('type', 'Unknown')} ({f.get('severity', 'Info')})"
        for f in top_findings[:3]
    ) or "No major vulnerability findings from subdomain scanner."

    return generate_pdf_report({
        "report_title": f"Website Report - {asset.get('name')}",
        "theme_color": "#0050cb",
        "secondary_theme_color": "#0f172a",
        "executive_summary": (
            f"Website {asset.get('name')} currently has {payload['summary']['subdomains_total']} discovered subdomains. "
            f"Active: {payload['summary']['subdomains_active']}, Inactive: {payload['summary']['subdomains_inactive']}. "
            f"Mobile apps discovered: {len(mobile_apps)}."
        ),
        "risk_score": payload["summary"]["risk_score"],
        "overall_risk": payload["summary"]["risk_level"],
        "summary_cards": [
            {"label": "Risk Score", "value": f"{payload['summary']['risk_score']}%", "color": "#dc2626" if payload["summary"]["risk_score"] < 40 else "#f59e0b" if payload["summary"]["risk_score"] < 80 else "#16a34a"},
            {"label": "TLS Version", "value": scan.get("tls_version", "Unknown"), "color": "#0050cb"},
            {"label": "Subdomains", "value": str(payload["summary"]["subdomains_total"]), "color": "#0f172a"},
            {"label": "Mobile Apps", "value": str(len(mobile_apps)), "color": "#16a34a"},
            {"label": "Active / Inactive", "value": f"{payload['summary']['subdomains_active']} / {payload['summary']['subdomains_inactive']}", "color": "#16a34a" if payload["summary"]["subdomains_inactive"] == 0 else "#f59e0b"},
        ],
        "chart_data": {
            "title": "Website Subdomain Status",
            "type": "pie",
            "labels": ["Active", "Inactive"],
            "values": [payload["summary"]["subdomains_active"], payload["summary"]["subdomains_inactive"]],
            "colors": ["#16a34a", "#dc2626"],
        },
        "subdomain_rows": payload.get("subdomains", []),
        "mobile_rows": [{"domain": asset.get("name"), "apps": mobile_apps}] if mobile_apps else [],
        "assets": [asset],
        "vulnerable_assets": [asset] if asset.get("risk", {}).get("risk_level") in ["High", "Critical"] else [],
        "recommendations": [
            "Review inactive subdomains for DNS cleanup and ownership drift.",
            "Prioritize TLS 1.3 adoption on lower-scoring subdomains.",
            "Rotate certificates and retire legacy crypto where applicable.",
            f"Top vulnerability observations: {top_findings_text}",
        ]
    })


def build_company_history_report_pdf(domain: str) -> bytes:
    matching_assets = _get_assets_for_domain(domain)
    if not matching_assets:
        raise HTTPException(status_code=404, detail="No scanned website found for the requested domain.")

    latest = matching_assets[0]
    latest_scan = latest.get("scan_result", {}) or {}
    domain_name = latest.get("name", _normalize_domain(domain))

    subdomain_map: Dict[str, dict] = {}
    for asset in matching_assets:
        scan_result = asset.get("scan_result", {}) or {}
        for row in scan_result.get("all_subdomains_detailed", []) or []:
            sub = row.get("subdomain")
            if sub and sub not in subdomain_map:
                subdomain_map[sub] = row

    mobile_rows = _build_mobile_rows_from_assets(matching_assets)
    risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for asset in matching_assets:
        level = str(asset.get("risk", {}).get("risk_level", "")).lower()
        if level in risk_counts:
            risk_counts[level] += 1

    return generate_pdf_report({
        "report_title": f"Domain Scan History Report - {domain_name}",
        "theme_color": "#0ea5e9",
        "secondary_theme_color": "#0f172a",
        "executive_summary": (
            f"This historical report consolidates {len(matching_assets)} scans for {domain_name}. "
            f"It includes subdomain posture evolution, vulnerability snapshots, and mobile discovery trends."
        ),
        "risk_score": latest.get("risk", {}).get("score", 0),
        "overall_risk": latest.get("risk", {}).get("risk_level", "Unknown"),
        "summary_cards": [
            {"label": "Total Scans", "value": str(len(matching_assets)), "color": "#0f172a"},
            {"label": "Latest Risk", "value": latest.get("risk", {}).get("risk_level", "Unknown"), "color": "#f59e0b"},
            {"label": "Subdomains", "value": str(len(subdomain_map)), "color": "#0050cb"},
            {"label": "Mobile Apps", "value": str(sum(len(r.get('apps', [])) for r in mobile_rows)), "color": "#16a34a"},
        ],
        "chart_data": {
            "title": "Risk Distribution Across Scans",
            "type": "bar",
            "labels": ["Low", "Medium", "High", "Critical"],
            "values": [risk_counts["low"], risk_counts["medium"], risk_counts["high"], risk_counts["critical"]],
            "color": "#0ea5e9",
        },
        "subdomain_rows": list(subdomain_map.values()),
        "mobile_rows": mobile_rows,
        "assets": matching_assets,
        "vulnerable_assets": [a for a in matching_assets if a.get("risk", {}).get("risk_level") in ["High", "Critical"]],
        "recommendations": [
            "Track risk score movement across consecutive scans and verify remediation impact.",
            "Validate mobile listings against official publisher ownership.",
            "Prioritize persistent critical subdomains with recurring vulnerability findings.",
            f"Latest TLS posture: {latest_scan.get('tls_version', 'Unknown')} / {latest_scan.get('algorithm', 'Unknown')}",
        ],
    })

def build_asset_discovery_report_pdf() -> bytes:
    payload = report_asset_discovery()
    summary = payload["summary"]
    return generate_pdf_report({
        "report_title": "Asset Discovery Report",
        "theme_color": "#0050cb",
        "secondary_theme_color": "#0f172a",
        "executive_summary": (
            f"Discovered {summary['total_domains']} domains. Active domains: {summary['active_domains']}, inactive domains: {summary['inactive_domains']}. "
            f"This report also tracks subdomain footprints per asset."
        ),
        "risk_score": summary["active_domains"],
        "overall_risk": "Moderate" if summary["inactive_domains"] > 0 else "Low",
        "summary_cards": [
            {"label": "Total Domains", "value": str(summary["total_domains"]), "color": "#0f172a"},
            {"label": "Active Domains", "value": str(summary["active_domains"]), "color": "#16a34a"},
            {"label": "Inactive Domains", "value": str(summary["inactive_domains"]), "color": "#dc2626"},
        ],
        "chart_data": {
            "title": "Domain Status Distribution",
            "type": "pie",
            "labels": ["Active", "Inactive"],
            "values": [summary["active_domains"], summary["inactive_domains"]],
            "colors": ["#16a34a", "#dc2626"],
        },
        "assets": [
            {
                "name": row.get("domain"),
                "type": row.get("asset_type", "Domain"),
                "risk": {"risk_level": row.get("status", "Unknown")},
                "scan_result": {
                    "algorithm": f"Active Subdomains: {row.get('active_subdomains', 0)}",
                    "tls_version": f"Inactive Subdomains: {row.get('inactive_subdomains', 0)}",
                },
                "subdomains": row.get("subdomains", []),
            }
            for row in payload.get("assets", [])
        ],
        "recommendations": [
            "Investigate inactive domains for DNS hygiene and ownership.",
            "Track active/inactive drift as part of weekly governance reviews."
        ]
    })

def build_subdomain_risk_report_pdf() -> bytes:
    payload = report_subdomain_risk()
    summary = payload["summary"]
    return generate_pdf_report({
        "report_title": "Subdomain Risk Classification Report",
        "theme_color": "#7c3aed",
        "secondary_theme_color": "#312e81",
        "executive_summary": (
            f"Total subdomains: {summary['total_subdomains']}. PQC Ready: {summary['pqc_ready']}, "
            f"Standard: {summary['standard']}, Critical: {summary['critical']}."
        ),
        "risk_score": summary["pqc_ready"],
        "overall_risk": "High" if summary["critical"] > 0 else "Low",
        "summary_cards": [
            {"label": "Total Subdomains", "value": str(summary["total_subdomains"]), "color": "#0f172a"},
            {"label": "PQC Ready", "value": str(summary["pqc_ready"]), "color": "#16a34a"},
            {"label": "Standard", "value": str(summary["standard"]), "color": "#f59e0b"},
            {"label": "Critical", "value": str(summary["critical"]), "color": "#dc2626"},
        ],
        "chart_data": {
            "title": "Subdomain Classification",
            "type": "bar",
            "labels": ["PQC Ready", "Standard", "Critical"],
            "values": [summary["pqc_ready"], summary["standard"], summary["critical"]],
            "color": "#7c3aed",
        },
        "subdomain_rows": payload.get("data", []),
        "recommendations": [
            "Prioritize critical subdomains with weak or expiring crypto posture.",
            "Promote standard subdomains into PQC-ready compliance baselines."
        ]
    })

def build_vulnerability_report_pdf() -> bytes:
    payload = report_vulnerabilities()
    summary = payload["summary"]
    return generate_pdf_report({
        "report_title": "Vulnerability & Hosting Report",
        "theme_color": "#dc2626",
        "secondary_theme_color": "#991b1b",
        "executive_summary": (
            f"Vulnerable domains: {summary['vulnerable_domains']}. High severity domains: {summary['high_severity_domains']}. "
            f"Third-party hosted: {summary['third_party_hosted']}."
        ),
        "risk_score": max(0, 100 - (summary["high_severity_domains"] * 10)),
        "overall_risk": "High" if summary["high_severity_domains"] > 0 else "Moderate",
        "summary_cards": [
            {"label": "Vulnerable Domains", "value": str(summary["vulnerable_domains"]), "color": "#dc2626"},
            {"label": "High Severity", "value": str(summary["high_severity_domains"]), "color": "#b91c1c"},
            {"label": "Third-Party Hosted", "value": str(summary["third_party_hosted"]), "color": "#f59e0b"},
        ],
        "chart_data": {
            "title": "Hosting / Severity Overview",
            "type": "bar",
            "labels": ["Vulnerable", "High Severity", "Third-Party"],
            "values": [summary["vulnerable_domains"], summary["high_severity_domains"], summary["third_party_hosted"]],
            "color": "#dc2626",
        },
        "vulnerable_assets": [
            {
                "name": row.get("domain"),
                "type": "Domain",
                "risk": {"risk_level": "High" if row.get("vulnerability_count", 0) > 0 else "Low"},
                "scan_result": {
                    "algorithm": ", ".join(v.get("type", "Unknown") for v in row.get("vulnerabilities", [])) or "None",
                    "tls_version": "3rd Party" if row.get("is_third_party") else "Internal",
                },
            }
            for row in payload.get("data", [])
        ],
        "recommendations": [
            "Remediate SQL Injection and XSS findings with immediate patch cycles.",
            "Review contracts and controls for third-party hosted critical assets."
        ]
    })

def build_mobile_app_report_pdf() -> bytes:
    payload = report_mobile_app()
    summary = payload["summary"]
    return generate_pdf_report({
        "report_title": "Mobile Application Discovery Report",
        "theme_color": "#16a34a",
        "secondary_theme_color": "#166534",
        "executive_summary": (
            f"Domains with mobile footprint: {summary['domains_with_mobile_apps']}. Total apps: {summary['total_apps']} "
            f"(Android: {summary['android_apps']}, iOS: {summary['ios_apps']})."
        ),
        "risk_score": 100 if summary["total_apps"] > 0 else 0,
        "overall_risk": "Low",
        "summary_cards": [
            {"label": "Domains with Apps", "value": str(summary["domains_with_mobile_apps"]), "color": "#16a34a"},
            {"label": "Total Apps", "value": str(summary["total_apps"]), "color": "#0f172a"},
            {"label": "Android", "value": str(summary["android_apps"]), "color": "#22c55e"},
            {"label": "iOS", "value": str(summary["ios_apps"]), "color": "#2563eb"},
        ],
        "chart_data": {
            "title": "Mobile Platform Split",
            "type": "bar",
            "labels": ["Android", "iOS"],
            "values": [summary["android_apps"], summary["ios_apps"]],
            "color": "#16a34a",
        },
        "mobile_rows": payload.get("data", []),
        "recommendations": [
            "Map discovered apps to official store listings and publisher accounts.",
            "Enforce release-signing and runtime hardening baselines for mobile channels."
        ]
    })

def _pdf_response(pdf_bytes: bytes, filename: str) -> Response:
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get("/api/reports/asset-discovery/download")
def download_asset_discovery_pdf(x_user_role: Optional[str] = Query(None), x_user_role_header: Optional[str] = Header(None)):
    role = resolve_role(x_user_role_header, x_user_role)
    require_admin_or_super(role)
    pdf_bytes = build_asset_discovery_report_pdf()
    date_prefix = datetime.datetime.now().strftime('%Y_%m_%d')
    return _pdf_response(pdf_bytes, f"{date_prefix}-Asset_Discovery_Report.pdf")

@app.get("/api/reports/subdomain-risk/download")
def download_subdomain_risk_pdf(x_user_role: Optional[str] = Query(None), x_user_role_header: Optional[str] = Header(None)):
    role = resolve_role(x_user_role_header, x_user_role)
    require_admin_or_super(role)
    pdf_bytes = build_subdomain_risk_report_pdf()
    date_prefix = datetime.datetime.now().strftime('%Y_%m_%d')
    return _pdf_response(pdf_bytes, f"{date_prefix}-Subdomain_Risk_Report.pdf")

@app.get("/api/reports/vulnerability/download")
def download_vulnerability_pdf(x_user_role: Optional[str] = Query(None), x_user_role_header: Optional[str] = Header(None)):
    role = resolve_role(x_user_role_header, x_user_role)
    require_admin_or_super(role)
    pdf_bytes = build_vulnerability_report_pdf()
    date_prefix = datetime.datetime.now().strftime('%Y_%m_%d')
    return _pdf_response(pdf_bytes, f"{date_prefix}-Vulnerability_Report.pdf")

@app.get("/api/reports/mobile-app/download")
def download_mobile_app_pdf(x_user_role: Optional[str] = Query(None), x_user_role_header: Optional[str] = Header(None)):
    role = resolve_role(x_user_role_header, x_user_role)
    require_admin_or_super(role)
    pdf_bytes = build_mobile_app_report_pdf()
    date_prefix = datetime.datetime.now().strftime('%Y_%m_%d')
    return _pdf_response(pdf_bytes, f"{date_prefix}-Mobile_App_Report.pdf")


@app.get("/api/reports/history")
def report_history(domain: Optional[str] = None, limit: int = 50):
    """Return report-like historical rows from prior scans, optionally filtered by domain."""
    limit = max(1, min(limit, 200))
    assets = _get_assets_for_domain(domain) if domain else sorted(
        get_all_assets_list(),
        key=lambda item: _parse_iso_datetime(item.get("detection_date", "")),
        reverse=True,
    )

    rows = []
    for asset in assets[:limit]:
        risk = asset.get("risk", {}) or {}
        detection_date = asset.get("detection_date") or ""
        scan = asset.get("scan_result", {}) or {}
        rows.append({
            "report_id": f"RP-{str(asset.get('id', 'NA'))[:8].upper()}",
            "timestamp": detection_date,
            "domain": asset.get("name"),
            "risk_level": risk.get("risk_level", "Unknown"),
            "score": risk.get("score", 0),
            "generated_by": asset.get("metadata", {}).get("scanned_by_role", "System"),
            "tls_version": scan.get("tls_version", "Unknown"),
            "algorithm": scan.get("algorithm", "Unknown"),
        })

    return {
        "report_type": "History",
        "summary": {
            "total": len(rows),
            "domain_filter": _normalize_domain(domain) if domain else None,
        },
        "data": rows,
    }


class CompanyEmailReportRequest(BaseModel):
    domain: str
    recipient: str
    include_history: bool = True


def send_company_report_email(recipient: str, domain: str, include_history: bool = True) -> dict:
    normalized_domain = _normalize_domain(domain)
    matching_assets = _get_assets_for_domain(normalized_domain)
    if not matching_assets:
        raise HTTPException(status_code=404, detail="No scan history found for the requested domain.")

    latest_asset = matching_assets[0]
    latest_risk = latest_asset.get("risk", {}) or {}
    attachments = [
        {
            "filename": f"{datetime.datetime.now().strftime('%Y_%m_%d')}-{normalized_domain}-Website_Report.pdf",
            "bytes": build_website_report_pdf(normalized_domain),
        }
    ]

    if include_history:
        attachments.append({
            "filename": f"{datetime.datetime.now().strftime('%Y_%m_%d')}-{normalized_domain}-History_Report.pdf",
            "bytes": build_company_history_report_pdf(normalized_domain),
        })

    summary = summarize_report({
        "domain": normalized_domain,
        "total_scans": len(matching_assets),
        "latest_risk": latest_risk,
        "latest_scan": latest_asset.get("scan_result", {}),
    })

    subject = f"Quantum Shield Domain Report - {normalized_domain} - {latest_risk.get('risk_level', 'Unknown')}"
    body = (
        f"Executive Summary:\n{summary}\n\n"
        f"Domain: {normalized_domain}\n"
        f"Total historical scans included: {len(matching_assets)}\n"
        f"Latest risk score: {latest_risk.get('score', 0)}\n"
        "Attachments include subdomain intelligence and mobile app discovery details."
    )

    success = send_email(recipient, subject, body, attachments)
    if success is not True:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {success}")

    return {
        "status": "success",
        "message": f"Report for {normalized_domain} sent to {recipient}",
        "domain": normalized_domain,
        "recipient": recipient,
        "attachments": [item["filename"] for item in attachments],
        "scan_count": len(matching_assets),
    }


@app.post("/api/reports/company/email")
def email_company_report(request: CompanyEmailReportRequest):
    """Send a domain-specific report bundle to email, including historical scans for that domain."""
    return send_company_report_email(request.recipient, request.domain, request.include_history)

# --- MODULE 9: AI CHATBOT ---
class ChatRequest(BaseModel):
    message: str

@app.post("/api/chat")
def chat_with_assistant(request: ChatRequest):
    """Processes user queries into actionable commands using hybrid parsing."""
    result = process_chat_message(request.message)
    
    if result["action"] == "SCHEDULE_SCAN":
        freq = result["parameters"].get("frequency", "daily")
        t = result["parameters"].get("time", "12AM")
        domain = result["parameters"].get("domain", "auto_discovery")
        email = result["parameters"].get("email", "admin@quantumshield.local")
        schedule_scan_job(freq, t, domain, email)
        result["response"] = result["explanation"]
        return result

    if result["action"] == "EMAIL_REPORT":
        recipient = result["parameters"].get("recipient", "admin@quantumshield.local")
        target_domain = result["parameters"].get("domain")
        if target_domain:
            outcome = send_company_report_email(recipient, target_domain, include_history=True)
            result["response"] = outcome["message"]
            return result

        risk_data = get_dashboard_metrics()
        all_assets = get_all_assets_list()
        vuln_assets = [a for a in all_assets if a.get("risk", {}).get("risk_level") in ["High", "Medium"]]
        
        # 1. Generate Summary
        summary = summarize_report({
            "metrics": risk_data["summary"],
            "high_risk_assets": len(risk_data["high_risk_assets"])
        })
        
        # 2. Structure Email
        overall_risk = "High" if risk_data["summary"]["high_risk"] > 0 else "Low"
        subject = f"Quantum Security Report - Risk Level: {overall_risk}"
        
        body = f"Executive Summary:\n{summary}\n\n"
        body += f"Risk Score: {risk_data['summary']['pqc_readiness_pct']}% PQC Ready\n"
        body += f"Key Findings: {risk_data['summary']['high_risk']} High Risk Assets, {risk_data['summary']['expiring_certs']} Expiring Certs\n"
        body += f"Recommendations: Upgrade legacy algorithms to NIST-compliant standards and prioritize rotating expiring certificates."

        attachments = [
            {"filename": f"{datetime.datetime.now().strftime('%Y_%m_%d')}-Asset_Discovery_Report.pdf", "bytes": build_asset_discovery_report_pdf()},
            {"filename": f"{datetime.datetime.now().strftime('%Y_%m_%d')}-Subdomain_Risk_Report.pdf", "bytes": build_subdomain_risk_report_pdf()},
            {"filename": f"{datetime.datetime.now().strftime('%Y_%m_%d')}-Vulnerability_Report.pdf", "bytes": build_vulnerability_report_pdf()},
            {"filename": f"{datetime.datetime.now().strftime('%Y_%m_%d')}-Mobile_App_Report.pdf", "bytes": build_mobile_app_report_pdf()},
        ]

        if target_domain:
            try:
                attachments.insert(0, {
                    "filename": f"{datetime.datetime.now().strftime('%Y_%m_%d')}-{target_domain}-Website_Report.pdf",
                    "bytes": build_website_report_pdf(target_domain)
                })
            except HTTPException:
                pass

        subject = f"Quantum Security Report Bundle - {target_domain or 'All Scans'} - Risk Level: {overall_risk}"
        body += f"\nReport Bundle: {len(attachments)} PDF attachments included."

        # 5. Send Email
        success = send_email(recipient, subject, body, attachments)
        
        # 5. Return API Response
        if success is True:
            result["response"] = f"Report with PDF successfully sent to {recipient}"
        else:
            result["response"] = f"SMTP ERROR. Gmail refused the connection: {success}. Please check your App Password."
            
        return result
        
        return result
        
    result["response"] = result["explanation"]
    return result

# --- MODULE 10: EMAIL & AUTH ---
import random

otp_store = {}

class OTPRequest(BaseModel):
    email: str
    password: str
    role: str

class OTPVerify(BaseModel):
    email: str
    otp: str

class DirectLoginRequest(BaseModel):
    role: str
    email: Optional[str] = None
    password: Optional[str] = None

def find_user_by_credentials(email: str, password: str, role: str):
    return next(
        (
            user for user in db_users.values()
            if str(user.get("username", "")).lower() == email.lower()
            and user.get("password") == password
            and user.get("role") == role
        ),
        None,
    )

def build_auth_session(user: dict) -> dict:
    return {
        "username": user.get("username"),
        "name": user.get("name"),
        "role": user.get("role")
    }

@app.post("/api/auth/send-otp")
def auth_send_otp(request: OTPRequest):
    if request.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role selected.")

    user = find_user_by_credentials(request.email, request.password, request.role)
    if not user:
        raise HTTPException(status_code=401, detail="User not found for selected role.")

    code = f"{random.randint(100000, 999999)}"
    otp_store[request.email.lower()] = {
        "otp": code,
        "role": user.get("role"),
        "name": user.get("name"),
        "username": user.get("username")
    }
    subject = "Quantum Shield Auth Code"
    body = f"Your secure 6-digit authentication code is: {code}\n\nThis code will expire shortly. Do not share it."
    send_email(request.email, subject, body)
    return {"message": "OTP sent successfully"}

@app.post("/api/auth/verify-otp")
def auth_verify_otp(request: OTPVerify):
    otp_record = otp_store.get(request.email.lower())
    if otp_record and otp_record.get("otp") == request.otp:
        del otp_store[request.email.lower()]
        return {
            "success": True,
            "role": otp_record.get("role"),
            "name": otp_record.get("name"),
            "username": otp_record.get("username")
        }
    raise HTTPException(status_code=400, detail="Invalid OTP code")

@app.post("/api/auth/direct-login")
def auth_direct_login(request: DirectLoginRequest):
    if request.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role selected.")

    if request.email and request.password:
        user = find_user_by_credentials(request.email, request.password, request.role)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials for selected role.")
    else:
        user = next((u for u in db_users.values() if u.get("role") == request.role), None)
        if not user:
            raise HTTPException(status_code=404, detail="No user found for selected role.")

    return {
        "success": True,
        **build_auth_session(user)
    }

class EmailRequest(BaseModel):
    recipient: str
    domain: Optional[str] = None
    include_history: bool = True

@app.post("/api/email")
def send_report(request: EmailRequest):
    """Email a domain-specific report bundle when a domain is provided; fallback to queue-style response otherwise."""
    if request.domain:
        return send_company_report_email(request.recipient, request.domain, request.include_history)
    return {"status": "success", "message": f"Enterprise Cryptographic Risk Report queued for {request.recipient}"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="0.0.0.0", port=8010, reload=False)
