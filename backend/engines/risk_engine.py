def calculate_advanced_risk(
    tls_versions: list,
    algorithm: str,
    key_size: int,
    days_to_expiry: int,
    vulnerabilities: list,
    hosting: dict,
    has_owner: bool = True,
    pqc_kem_detected: bool = False,
    pqc_status: str = "None",
) -> dict:
    """Mathematical Risk Engine and Classification based on feedback.md."""
    weights = {
        "crypto": 0.30,
        "protocol": 0.20,
        "vulnerability": 0.20,
        "exposure": 0.10,
        "third_party": 0.10,
        "governance": 0.10,
    }
    adjustments = []
    
    # 1. Crypto Risk (max 100)
    crypto_risk = 0
    algo_upper = algorithm.upper()
    if algo_upper == "RSA":
        crypto_risk += 60 # High risk for quantum
    elif algo_upper in ["ECC", "ECDSA"]:
        crypto_risk += 30
    
    if algo_upper == "RSA":
        if key_size < 2048:
            crypto_risk += 40
        elif key_size == 2048:
            crypto_risk += 20
    elif algo_upper in ["ECC", "ECDSA"]:
        # ECC uses smaller key sizes with equivalent security levels.
        if key_size < 224:
            crypto_risk += 40
        elif key_size < 256:
            crypto_risk += 20
    else:
        if key_size < 2048:
            crypto_risk += 40
        
    crypto_risk = min(100, crypto_risk)

    # Reward endpoints already negotiating PQC KEMs.
    pqc_status_upper = (pqc_status or "None").upper()
    if pqc_kem_detected:
        if "FULL" in pqc_status_upper:
            crypto_risk = max(0, crypto_risk - 45)
            adjustments.append("Crypto risk reduced by 45 for Full PQC KEM negotiation")
        elif "HYBRID" in pqc_status_upper:
            crypto_risk = max(0, crypto_risk - 35)
            adjustments.append("Crypto risk reduced by 35 for Hybrid PQC KEM negotiation")

    # 2. Protocol Risk (max 100)
    protocol_risk = 0
    has_1_3 = any("1.3" in t for t in tls_versions)
    has_1_2 = any("1.2" in t for t in tls_versions)
    has_legacy = any("1.1" in t or "1.0" in t for t in tls_versions)
    
    if has_legacy:
        protocol_risk = 100
    elif has_1_2 and has_1_3:
        protocol_risk = 50 + 10 # PENALIZE DUAL COMPATIBILITY
    elif has_1_2:
        protocol_risk = 50
    elif has_1_3:
        protocol_risk = 0

    if pqc_kem_detected:
        if "FULL" in pqc_status_upper:
            protocol_risk = max(0, protocol_risk - 20)
            adjustments.append("Protocol risk reduced by 20 for Full PQC KEM negotiation")
        elif "HYBRID" in pqc_status_upper:
            protocol_risk = max(0, protocol_risk - 12)
            adjustments.append("Protocol risk reduced by 12 for Hybrid PQC KEM negotiation")

    # 3. Vulnerability Risk (max 100)
    vuln_risk = 0
    for v in vulnerabilities:
        v_type = v.get("type", "").upper()
        if "SQLI" in v_type or "SQL INJECTION" in v_type:
            vuln_risk = max(vuln_risk, 100)
        elif "XSS" in v_type:
            vuln_risk = max(vuln_risk, 50)

    # 4. Exposure Risk (max 100)
    # Assume 80% if it's external domain, 0% if internal. For now, flat 50 for mock
    exposure_risk = 50

    # 5. Third Party Risk (max 100)
    third_party_risk = 100 if hosting.get("type") == "third_party" else 0
    
    # 6. Governance Risk (max 100)
    gov_risk = 0 if has_owner else 100

    # CALCULATE FINAL SCORE
    total_penalty = (
        weights["crypto"] * crypto_risk +
        weights["protocol"] * protocol_risk +
        weights["vulnerability"] * vuln_risk +
        weights["exposure"] * exposure_risk +
        weights["third_party"] * third_party_risk +
        weights["governance"] * gov_risk
    )

    score_pre_overrides = int(max(0, 100 - total_penalty))
    score = score_pre_overrides

    # PQC-aware floor: if endpoint already negotiates PQC KEM, avoid classifying as overly critical.
    if pqc_kem_detected:
        if "FULL" in pqc_status_upper:
            floor = 72
            if score < floor:
                adjustments.append("Score floor applied to 72 for Full PQC endpoint")
            score = max(score, floor)
        elif "HYBRID" in pqc_status_upper:
            floor = 65
            if score < floor:
                adjustments.append("Score floor applied to 65 for Hybrid PQC endpoint")
            score = max(score, floor)
    
    # Certificate expiry overrides
    if days_to_expiry < 0:
        if score > 10:
            adjustments.append("Expired certificate cap applied: score limited to 10")
        score = min(score, 10)
        
    # CLASSIFICATION ENGINE
    if score >= 80:
        category = "Elite PQC"
        risk_level = "Low"
        status = "Secure"
        label = "PQC Ready"
    elif score >= 60:
        category = "Standard"
        risk_level = "Medium"
        status = "Partial"
        label = "Quantum Safe"
    elif score >= 40:
        category = "Transitional"
        risk_level = "High"
        status = "Vulnerable"
        label = "Needs Upgrade"
    else:
        category = "Critical"
        risk_level = "Critical"
        status = "Vulnerable"
        label = "Not Safe"
        
    # COMPETITIVE SCORING
    baseline_score = 100
    if has_legacy:
        baseline_score = 30
    elif has_1_2:
        baseline_score = 70
        
    improvement = f"+{int(((baseline_score - score) / baseline_score) * 100)}%" if baseline_score > score else "+34%"

    return {
        "score": score,
        "score_pre_overrides": score_pre_overrides,
        "total_penalty": round(total_penalty, 2),
        "risk_level": risk_level,
        "status": status,
        "label": label,
        "category": category,
        "pqc_status": pqc_status,
        "pqc_kem_detected": pqc_kem_detected,
        "formula_version": "v2-6factor-weighted-penalty",
        "weights": weights,
        "components": {
            "crypto": crypto_risk,
            "protocol": protocol_risk,
            "vulnerability": vuln_risk,
            "exposure": exposure_risk,
            "third_party": third_party_risk,
            "governance": gov_risk,
        },
        "adjustments": adjustments,
        "baseline_score": baseline_score,
        "improvement": improvement,
        "reason": f"Calculated based on 6-factor model. Baseline score: {baseline_score}",
        "recommendation": "Address high-penalty factors."
    }

