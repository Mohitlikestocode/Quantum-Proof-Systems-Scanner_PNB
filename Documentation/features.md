# Quantum Shield PNB - Complete Feature Documentation

## Why This Document Exists

This is the master feature sheet for Quantum Shield PNB.
It is designed for presentation use, so it does three things:

1. Lists the full website capability set in one place.
2. Highlights newly added features clearly.
3. Explains business and security impact with practical examples.

---

## Product Snapshot

Quantum Shield PNB is a security intelligence platform that combines:

- live domain and subdomain scanning,
- TLS and certificate intelligence,
- PQC (Post-Quantum Cryptography) readiness tracking,
- vulnerability discovery,
- mobile app footprint discovery,
- risk scoring,
- AI-assisted reporting,
- and governance-ready PDF/email workflows.

In short: this is not a static dashboard. It is an active cyber defense control plane.

---

## New Highlights (Recently Added)

These are the highest-impact additions made recently and should be emphasized in your PPT.

### 1) Advanced Subdomain Discovery and Expansion [NEW]

- Discovers subdomains via Certificate Transparency logs (crt.sh).
- Performs DNS candidate probing for common infrastructure hostnames.
- Expands from certificate SAN values (including one extra expansion pass).
- Scans discovered hosts and separates active vs inactive assets.

Why it matters:
Attackers do not stop at the root domain. This closes the visibility gap on shadow endpoints.

Example:
If main domain is protected but api.domain.com is weak, the platform still detects and surfaces it.

### 2) Real Subdomain Vulnerability Scanner [NEW]

- Runs checks on discovered subdomains, not only the root domain.
- Detects multiple vulnerability classes including:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Open Redirect
  - Security Misconfiguration / missing hardening headers
  - Sensitive exposure indicators
  - CORS and directory listing style weaknesses
- Produces top findings, severity breakdown, and type counts.

Why it matters:
Risk is often hidden in forgotten subdomains. This feature finds exploitable exposure where attackers usually look first.

Example:
An attacker fuzzes id parameters on legacy subdomains. The platform flags SQL error signatures and elevates domain risk.

### 3) Kyber / MLKEM / Hybrid PQC Detection [NEW]

- Detects PQC KEM and hybrid negotiation indicators.
- Maps Kyber-family and MLKEM-related groups.
- Classifies posture into practical states:
  - None
  - PQC Signature Only
  - Hybrid PQC
  - Full PQC
- Exposes PQC detection notes for explainability.

Why it matters:
This directly supports quantum-readiness decisions instead of guessing based on marketing claims.

Example:
Two domains both show TLS 1.3, but only one negotiates hybrid PQC. The platform can prioritize migration of the other.

### 4) Full Deep Scan vs Quick Scan Modes [NEW]

- Quick mode: faster limits for triage.
- Deep mode: broader subdomain + vulnerability coverage.
- Mode is captured in scan metadata for reporting consistency.

Why it matters:
Teams can choose speed during incident triage and depth during audit cycles.

### 5) Handshake Status Intelligence in Scanner UI [NEW]

- Explicitly shows whether TLS handshake succeeded or failed.
- Displays useful failure context instead of a vague generic error.
- Improves operator trust in scan output.

Why it matters:
Security teams need to distinguish true target weakness from connectivity/timeouts.

### 6) Domain-Specific Company Email Report Bundles [NEW]

- Send report packs for one selected domain/company.
- Optional inclusion of domain history report.
- Attachments can include website report + historical trend report.
- Validates domain and email inputs before dispatch.

Why it matters:
Executives and domain owners receive focused, actionable intelligence rather than noisy platform-wide dumps.

Example:
Send only google.com security package to an owner email with latest risk posture and historical trajectory.

### 7) Live Report History and Filtering [NEW]

- Historical report view with domain filter.
- Includes risk level, score, generated time, TLS/algorithm context.
- Enables trend storytelling and governance reviews.

Why it matters:
Security maturity is about trajectory, not one-time snapshots.

### 8) AI-Resilience Hardening Controls [NEW]

- Endpoint rate limiting by action class (scan, chat, email, report, auth).
- Domain/email validation with strict patterns.
- Blocks private, loopback, and reserved targets to reduce SSRF-style misuse.
- Security response headers middleware.
- Chat input size limits.
- LLM summary prompt hardening (treat scan JSON as untrusted data).

Why it matters:
Prevents abuse of the platform itself as a reconnaissance or spam engine.

---

## Complete Feature Catalog (End-to-End)

## A) Platform and Navigation

- Login-driven session handling with role context.
- Multi-module workspace:
  - Dashboard
  - Asset Inventory
  - Asset Discovery
  - Scanner
  - CBOM
  - PQC Posture
  - Cyber Rating
  - Reports
  - AI Assistant

Value:
Single pane of glass for technical teams and leadership.

## B) Scanner and Discovery Engine

- Domain normalization and validation before scan.
- Root + subdomain coverage.
- Concurrent scanning for performance.
- Active/inactive classification.
- Source-aware discovery counters (crt.sh, DNS, SAN).
- SAN expansion from scanned hosts.

Value:
Comprehensive attack-surface mapping with source explainability.

## C) TLS and Certificate Intelligence

- Live TLS handshake probe.
- Negotiated TLS version and cipher suite extraction.
- Certificate issuer and expiry extraction.
- Key algorithm and key size classification.
- Days-to-expiry tracking.
- SSL rating logic.

Value:
Immediate visibility into cryptographic hygiene and certificate risk.

## D) Post-Quantum Readiness

- PQC KEM/hybrid detection pipeline.
- PQC signature signal detection.
- PQC status classification for readiness reporting.
- Kyber-family labeling support in UI.

Value:
Supports phased migration toward NIST-era post-quantum posture.

## E) Vulnerability Intelligence

- Root-domain vulnerability probe support.
- Subdomain vulnerability scan pipeline.
- Severity scoring and top findings output.
- Vulnerability type distribution for reporting.

Value:
Findings are tied to concrete evidence and subdomain context.

## F) Mobile App Discovery

- Android + iOS discovery flow.
- Brand-hint and acronym-aware matching.
- Relevance-ranked app list.
- Most relevant app surfaced for analysts.

Value:
Covers non-web exposure where brand abuse and impersonation often happen.

## G) Risk Engine and Scoring

- Multi-factor risk scoring combining:
  - crypto posture,
  - protocol posture,
  - vulnerability signals,
  - exposure assumptions,
  - third-party hosting influence,
  - governance ownership signal.
- Risk categorization labels (Low/Medium/High/Critical aligned outputs).
- PQC-aware floor logic to avoid over-penalizing hybrid/full PQC endpoints.

Value:
Converts technical telemetry into decision-ready priorities.

## H) Dashboard Intelligence

- Live summary cards:
  - total assets,
  - APIs,
  - servers,
  - expiring certificates,
  - PQC readiness,
  - high-risk assets.
- Vulnerability heatmap representation.
- Risk profile trend visualization.
- Recent inventory table with TLS/key context.

Value:
Leadership-level visibility without losing technical traceability.

## I) Reporting and Export System

- Modular reports:
  - Asset Discovery
  - Subdomain Risk
  - Vulnerability
  - Mobile App
- JSON and PDF report outputs.
- Website/domain-specific PDF report generation.
- Full CISO-grade export path (role-gated).
- Vulnerable-only report export.

Value:
Bridges technical operations and governance/compliance communication.

## J) Historical Reporting and Auditability

- Report history endpoint with filter and bounded limits.
- Domain-specific historical consolidation.
- Historical risk posture support in email/report flows.

Value:
Enables quarterly review narratives and improvement tracking.

## K) Scheduling and Automation

- Recurring scan scheduling:
  - daily
  - weekly
  - monthly
- day-of-week/day-of-month controls.
- next-run visibility.
- scheduled execution + report generation + email dispatch.

Value:
Moves security from ad hoc scanning to operational cadence.

## L) AI Assistant and Automation

- Natural language command interpretation for actions like:
  - scan domain
  - schedule scan
  - email report
  - show vulnerable assets
- action-oriented response model.
- executive summary generation support.

Value:
Faster operations for non-technical stakeholders and SOC workflows.

## M) Security Hardening and Abuse Resistance

- Request rate limiting by endpoint class.
- strict domain and recipient validation.
- restricted target policy (no localhost/private/reserved abuse).
- defensive security headers middleware.
- bounded chat payload size.
- prompt-injection-aware LLM summary strategy.

Value:
Hardens the platform against AI-scale abuse patterns.

---

## Why This Platform Is Strong Against AI-Driven Threats

Borrowing directly from the AI resilience architecture:

- It narrows attacker-defender visibility gaps via deep discovery.
- It prioritizes evidence-based scanning over assumptions.
- It reduces automation abuse through validation and rate limiting.
- It prevents direct model-instruction trust (prompt hardening).
- It distributes intelligence fast through focused report bundles.

One-line value statement:
The platform helps defenders operate at AI speed without turning the system into an attacker utility.

---

## Presentation-Ready Impact Examples

### Example 1: Hidden Subdomain Risk

Scenario:
The root domain appears healthy.

What Quantum Shield PNB does:
- discovers subdomain cluster,
- finds one inactive and one vulnerable endpoint,
- shows critical findings in report and risk profile.

Outcome:
Security team remediates exposed edge service before exploitation.

### Example 2: SQL Injection on a Buried Endpoint

Scenario:
A forgotten query parameter on an old subdomain starts leaking SQL-style error patterns.

What Quantum Shield PNB does:
- vulnerability scanner flags SQL Injection class,
- severity breakdown increases High count,
- domain report highlights top finding and affected subdomain.

Outcome:
Owner receives domain-specific report and patches endpoint quickly.

### Example 3: Quantum Migration Prioritization

Scenario:
Multiple business-critical domains all claim modern TLS.

What Quantum Shield PNB does:
- distinguishes classical-only vs hybrid PQC posture,
- quantifies readiness and risk,
- drives prioritized migration plan.

Outcome:
Budget and remediation focus align to actual cryptographic gap, not assumptions.

### Example 4: AI Abuse Attempt Against Chat/Email Flows

Scenario:
Automated attacker attempts high-volume scan/email/chat abuse.

What Quantum Shield PNB does:
- rate limits and input validation block misuse patterns,
- rejects malformed domains/emails,
- prevents unsafe model-driven command behavior.

Outcome:
Platform remains operational and trustworthy for genuine users.

---

## Suggested PPT Slide Structure

1. Problem and threat landscape (AI-accelerated attacks).
2. Platform overview (control plane, not static dashboard).
3. New highlights (subdomain, SQLi scanner, Kyber/MLKEM detection, hardening).
4. End-to-end workflow (scan -> score -> report -> email).
5. Evidence-based examples (4 scenarios above).
6. Business value (faster remediation, better governance, reduced blind spots).
7. Next roadmap (RBAC depth, audit trails, alerting, vault-backed secrets).

---

## Executive Closing

Quantum Shield PNB now delivers broad attack-surface visibility, real vulnerability and crypto intelligence, strong post-quantum posture tracking, and AI-resilient operational controls in one integrated platform.

For presentation language:
"We transformed security from static monitoring into an evidence-driven, automation-ready defense system that can keep pace with AI-era attackers."
