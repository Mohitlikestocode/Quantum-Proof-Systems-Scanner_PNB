🏗️ SYSTEM UPGRADE STRATEGY

Existing system (your current build):

Basic scanner
Dashboard
Some risk logic

Upgrade to:

🔥 NEW CAPABILITIES (MANDATORY)
Full Scan = Domain + Subdomains
Structured JSON → Classification Engine
Mathematical Scoring Model (weighted)
Competitive Scoring vs baseline
4-Type Reporting System
Mobile App Discovery
Vulnerability + Hosting Intelligence
RBAC (Super Admin / Admin / User)
Governance Layer (audit + review)
TLS Dual Compatibility Penalty
🔍 MODULE 1: FULL ASSET DISCOVERY (UPGRADE)
🎯 Requirement

“Full scan means domain + subdomains”

Implementation:
Input: bank.com

Output:
{
  "root_domain": "bank.com",
  "subdomains": [
    "login.bank.com",
    "api.bank.com",
    "vpn.bank.com"
  ],
  "total_assets": 40,
  "active_assets": 32,
  "inactive_assets": 8
}
Classification:
Active → responds to request
Inactive → DNS exists but no service
🔐 MODULE 2: CRYPTO + TLS ANALYSIS (UPGRADE)

Extract:

TLS versions (ALL supported)
Preferred TLS
Cipher suites
Key algorithm (RSA / ECC / AES)
Key size
Certificate expiry
⚠️ IMPORTANT (Mentor Feedback)

Penalize dual compatibility

Logic:
if TLS includes both 1.2 AND 1.3:
    penalty += 10   # transitional weakness

if TLS includes 1.0 or 1.1:
    penalty += 30   # critical
🧠 MODULE 3: MATHEMATICAL RISK ENGINE (NEW)
🎯 Requirement

“Use better mathematical calculation”

🧮 FORMULA
RiskScore = 100 - (
    0.30 * CryptoRisk +
    0.20 * ProtocolRisk +
    0.20 * VulnerabilityRisk +
    0.10 * ExposureRisk +
    0.10 * ThirdPartyRisk +
    0.10 * GovernanceRisk
)
🔍 SUB-SCORES
CryptoRisk
RSA / ECC → high risk (quantum)
Weak key size → high
ProtocolRisk
TLS 1.0/1.1 → critical
TLS 1.2 → moderate
TLS 1.3 → safe
VulnerabilityRisk
SQL Injection → high
XSS → medium
ExposureRisk
Public-facing APIs → higher risk
ThirdPartyRisk
Hosted on AWS / external infra → +risk tag
GovernanceRisk
No owner assigned
No review logs
📊 MODULE 4: CLASSIFICATION ENGINE (NEW)
🎯 Requirement

“Classify based on JSON output”

Input:

Full JSON from scanner

Output:
{
  "score": 72,
  "category": "Standard",
  "risk_level": "Medium",
  "color": "orange"
}
Categories:
Score	Label
80–100	Elite PQC
60–79	Standard
40–59	Transitional
<40	Critical
⚔️ MODULE 5: COMPETITIVE SCORING (NEW)
🎯 Requirement

“Compare with existing model”

Baseline Model:
Only scans root domain
Only checks TLS version
Your Model:
Full asset scan
Multi-factor scoring
Formula:
CompetitiveScore =
    0.4 * CoverageImprovement +
    0.3 * RiskDetectionDepth +
    0.3 * Actionability
Output:
{
  "baseline_score": 58,
  "qshield_score": 78,
  "improvement": "+34%"
}
📄 MODULE 6: REPORT SYSTEM (CRITICAL)
🎯 Requirement

“Split into 4 reports”

1️⃣ ASSET DISCOVERY REPORT
All domains + subdomains
Active vs inactive
Total count
2️⃣ SUBDOMAIN RISK REPORT
Each subdomain score
Classification:
15 → PQC Ready
10 → Standard
15 → Critical
3️⃣ VULNERABILITY REPORT
SQLi, XSS
Hosting info:
hosted_on: AWS → third_party = true
4️⃣ MOBILE APP REPORT
Apps found:
{
  "android": ["mobx.app.bank"],
  "ios": ["bank_secure_ios"]
}
Risk score per app
📱 MODULE 7: MOBILE DISCOVERY (NEW)
🎯 Requirement

“Detect mobile apps (Play Store / iTunes)”

Logic:
Search keywords:
bank name
mobile banking
Match:
package name
app title
Output:
{
  "mobile_apps_found": 2,
  "apps": [
    {
      "platform": "android",
      "name": "Bank Mobile",
      "risk_score": 68
    }
  ]
}
🛡️ MODULE 8: VULNERABILITY + HOSTING
🎯 Requirement

“Detect SQLi, XSS, hosting ownership”

Output:
{
  "vulnerabilities": [
    {"type": "SQL Injection", "severity": "High"},
    {"type": "XSS", "severity": "Medium"}
  ],
  "hosting": {
    "provider": "AWS",
    "type": "third_party"
  }
}
👥 MODULE 9: RBAC + GOVERNANCE (CRITICAL)
🎯 Requirement

“Admin, Super Admin, User + control”

Roles:
👤 USER
View basic reports only
🛠 ADMIN
Run scans
Manage users
👑 SUPER ADMIN
Create users
Access CISO reports
Governance control
RULES:
Only super admin can create users
Admin CANNOT create super admin
Only 1 super admin (unless transferred)
GOVERNANCE FEATURES:
Access logs
Report access tracking
Review status:
last_reviewed: date
reviewed_by: admin
📄 MODULE 10: JSON MASTER OUTPUT

This is your core system output.

{
  "asset": "login.bank.com",
  "status": "active",
  "tls": {...},
  "vulnerabilities": [...],
  "hosting": {...},
  "mobile": {...},
  "score": 72,
  "category": "Standard",
  "risk": "Medium"
}





Informal *Feedback received*
- subdomains, not only domains for scanning. 
- use a better mathematical calculation
- json output - go through it, what all parameters are ignored, use help of it.
- full scan means domain and subdomain
- classify based on output of json
- compare and create and competitivee score with an existing model.
- Website particular report
- Penalizing dual compatibility in case of TLS protocols and giving it s worse risk score
- level access (user access - 3 steps) + governance and review user access review
- How can it get controlled - admin, super admin, normal user.  In reporting part CISO reporting only to super admin.
- Super admin can create user 
- Admin cannot create super admin, only 1 super admin (based on requirement - can get created by another super admin)
- user will get normal reports...so it shall be used in governance
- Scanning the assets, and coming in report - in the report split it into 4 kinds of reports
- Mainpuralbank has 40 domains, our scan should show all domains.  Active domains and inactive domains (1 report), anotehr report (inside subdomains - give rating to each subdomain and that rating you can segregate the assets critical, non critical etc) eg 15 subdomains are PQC readiness, then standard, elite - 10 assets. 15 assets are in critical stage. 
- Do report based 
- Mobile part discovery - manipular bank has how many mobile apps? In itunes, android. Eg out of 40, 2 are mobile apps dc and dr. Mobx (key words etc). These are all mobile banking apps. Iphone store, android playstore.  What is the rating? 
- Vulnerability scanning (Cross side scriping, server cross side scripiting, sql injection, hosting - hosted in domain/subdomain environment...eg - if the owner is aamazong webs erverices instead of maniupral bank, then segreagate it as 3rd party)
- Out of 45, 20 would be servers, out of all vulnerability scaning. If it's succestuable to sql injection, scripting. Then we shall implement it. 
- Mobile friendly - It is having mobile friendly features. It will be helpful for super admins. 90% would be ciso, departemnt heads...