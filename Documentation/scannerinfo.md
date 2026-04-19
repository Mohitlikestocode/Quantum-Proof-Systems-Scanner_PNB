# Scanner Info

This document is the code-level reference for the scanner. It explains exactly what the scanner does, which functions run, what data they produce, what is real versus synthetic, and how the frontend consumes the result.

## 1. Purpose

The scanner is a domain-based cryptographic exposure pipeline. It does not just check one TLS endpoint. It:
1. Normalizes the target domain.
2. Tries to discover real subdomains.
3. Probes TLS and certificate details for the root host and discovered subdomains.
4. Computes a risk score from the collected cryptographic and exposure signals.
5. Returns one consolidated JSON response to the UI and to the in-memory asset store.

The important thing to understand is that the scanner has two kinds of values:
1. Raw scan values, which reflect what the network actually returned.
2. Normalized risk inputs, which are fallback values used only so the risk engine can still score a target even when the raw probe fails.

That separation is deliberate and now enforced in `backend/main.py`.

## 2. Main Files And Responsibilities

### `backend/engines/scanner.py`
This is the core scanner engine. It contains:
1. `_parse_certificate`
2. `_resolve_ips`
3. `_probe_tls_versions`
4. `attempt_ssl_handshake`
5. `_derive_ssl_rating`
6. `get_subdomain_scan_data`
7. `discover_subdomains`
8. `discover_mobile_apps`
9. `discover_vulnerabilities`
10. `scan_target`

### `backend/main.py`
This file exposes the API route `POST /api/scan` and turns the scan output into an asset record. It also prepares normalized fallback values for risk scoring.

### `backend/engines/risk_engine.py`
This file contains `calculate_advanced_risk(...)`, which converts TLS, certificate, vulnerability, hosting, and governance factors into one score.

### `src/components/Scanner.tsx`
This is the UI entrypoint. It sends the scan request, handles success/failure, and renders the returned fields.

## 3. UI To Backend Flow

The frontend scan button calls `handleScan()` in `src/components/Scanner.tsx`.

The code path is:
1. Read the input target from `target` state.
2. Send `POST` to `${apiBase}/api/scan`.
3. Send JSON body:
   - `domain: target`
   - `mode: "Full Deep Scan"`
4. Read the JSON response.
5. If the HTTP status is not OK, throw the backend error detail.
6. If successful, set the full response into `scanResult` and render the result panels.

The UI reads these paths directly:
1. `scanResult.scan_result.tls_version`
2. `scanResult.scan_result.cipher_suite`
3. `scanResult.scan_result.algorithm`
4. `scanResult.scan_result.key_size`
5. `scanResult.scan_result.certificate_issuer`
6. `scanResult.scan_result.expiry_date`
7. `scanResult.scan_result.ipv4`
8. `scanResult.scan_result.ipv6`
9. `scanResult.scan_result.all_subdomains_detailed`
10. `scanResult.risk.score`
11. `scanResult.risk.risk_level`

## 4. API Route Logic

The main scanner route is `POST /api/scan` in `backend/main.py`.

### What it does
1. Receives `ScanRequest` with `domain` and optional `mode`.
2. Calls `scan_target(domain)` from `backend/engines/scanner.py`.
3. Pulls out raw values from the scan response.
4. Builds normalized fallback inputs only for the risk engine.
5. Calls `calculate_advanced_risk(...)`.
6. Stores an asset record in `db_assets`.
7. Appends a node to `db_nodes` for graph view.
8. Returns the full asset record.

### Raw vs normalized data

Raw scan values are kept intact in `scan_result`:
1. `tls_version`
2. `tls_versions_list`
3. `cipher_suite`
4. `key_size`
5. `certificate_issuer`
6. `expiry_date`
7. `algorithm`
8. `days_to_expiry`
9. `ipv4`
10. `ipv6`

The route also adds:
1. `risk_input.tls_versions`
2. `risk_input.algorithm`
3. `risk_input.key_size`
4. `risk_input.days_to_expiry`

Those `risk_input` values are what the risk engine should treat as safe scoring inputs if the raw probe failed.

## 5. Input Normalization

`scan_target(domain)` starts by normalizing the input:
1. Lowercases the string.
2. Removes `http://`.
3. Removes `https://`.
4. Removes anything after the first `/`.

Example:
- `HTTPS://Example.com/path` becomes `example.com`

This matters because the discovery and TLS routines expect a bare hostname.

## 6. Real Subdomain Discovery

`discover_subdomains(domain)` is the subdomain discovery driver.

It merges three sources and then performs one extra SAN expansion pass:
1. Certificate Transparency (`crt.sh`)
2. DNS resolution against common hostname prefixes
3. SAN entries from the main domain certificate, when available
4. SAN entries collected from already-active discovered subdomains

### 6.1 crt.sh source

The code calls:

```text
https://crt.sh/?q=%.<domain>&output=json
```

For each returned cert entry:
1. Read `name_value`.
2. Split by line.
3. Trim and lowercase.
4. Remove a leading `*.` wildcard if present.
5. Keep only names that end with the target domain and are not the root domain itself.

This is a passive discovery source. It only finds what was already published in certificate logs.

### 6.2 DNS prefix enumeration

The scanner also tests a fixed list of likely hostnames such as:
1. `www`
2. `api`
3. `app`
4. `portal`
5. `admin`
6. `auth`
7. `login`
8. `mail`
9. `cdn`
10. `static`
11. `dev`
12. `test`
13. `staging`
14. `status`
15. `docs`

These are combined as `<prefix>.<domain>` and checked with `socket.getaddrinfo(...)`.

Implementation details:
1. DNS checks run concurrently via `ThreadPoolExecutor`.
2. A candidate is kept only if resolution succeeds.
3. This is not fake data; it is actual DNS resolution.

### 6.3 SAN enrichment

If the root TLS handshake succeeds, SAN DNS names from the certificate are also added.

That means a successful certificate handshake can contribute more names even if crt.sh is empty.

### 6.4 In-scan SAN expansion

After the first subdomain scan pass finishes, the scanner collects SAN DNS names from:
1. the main domain probe, and
2. every active subdomain that was already scanned.

Any new names are then scanned once more inside the same request.

This is the reason the scanner can now surface a larger set on the first run instead of waiting for a second manual scan.

### Discovery metrics in output

The response includes source counters:
1. `summary.discovery_sources.crtsh`
2. `summary.discovery_sources.dns`
3. `summary.discovery_sources.certificate_san`

These counters make it obvious where subdomains came from.

## 7. TLS Handshake And Certificate Parsing

### 7.1 `attempt_ssl_handshake(domain, port=443, timeout=5)`

This function tries a real TLS client handshake:
1. Create a TLS client context.
2. Disable certificate verification and hostname checking for probing.
3. Open a TCP socket to the host on port 443.
4. Wrap the socket in TLS.
5. Measure handshake latency with `time.perf_counter()`.
6. Read the peer certificate in DER format.
7. Record the negotiated TLS version and cipher suite.

If the handshake fails, the function returns:
1. `is_active = False`
2. `error` with the real exception message
3. `status = "inactive"`

### 7.2 `_parse_certificate(der_bytes)`

This function extracts:
1. Issuer common name
2. Expiry date
3. Days to expiry
4. Certificate algorithm family
5. Public key size
6. SAN DNS names

Algorithm detection:
1. RSA public key -> `RSA`
2. Elliptic curve public key -> `ECC`
3. Anything else -> `Unknown`

The code now handles timezone-aware certificate timestamps correctly.

### 7.3 `_probe_tls_versions(domain)`

The scanner also attempts one handshake each for:
1. TLS 1.3
2. TLS 1.2
3. TLS 1.1
4. TLS 1.0

Each probe is isolated by pinning `minimum_version` and `maximum_version` to the same TLS version.

The return value is a list of labels such as:
- `TLS 1.3`
- `TLS 1.2`

## 8. Per-Host Scan Data

`get_subdomain_scan_data(subdomain, port=443)` is the per-host scanner.

### If the handshake succeeds

It returns:
1. `status = "active"`
2. `is_active = True`
3. `connection_successful = True`
4. `tls_versions`
5. `cipher_suite`
6. `key_size`
7. `certificate_issuer`
8. `expiry_date`
9. `days_to_expiry`
10. `algorithm`
11. `response_time_ms`
12. `certificate_valid`
13. `ssl_rating`
14. `san_domains`
15. `negotiated_tls_version`

### If the handshake fails

It returns:
1. `status = "inactive"`
2. `is_active = False`
3. `connection_successful = False`
4. `tls_versions = []`
5. `cipher_suite = "No TLS handshake"`
6. `certificate_issuer = "Unavailable"`
7. `expiry_date = None`
8. `algorithm = "Unavailable"`
9. `ssl_rating = "N/A"`
10. `error` with the actual exception text

That is why you may see `Unavailable` for some domains. It means the host did not complete a TLS handshake from this network path.

## 9. Main Endpoint Selection

The scanner now separates the root host probe from the effective primary endpoint used for the main scan response.

### Selection rules
1. If the root host is active, use the root host.
2. Otherwise, prefer an active discovered `www`, `app`, or `portal` host.
3. Otherwise, use the first active discovered subdomain.
4. Otherwise, keep the root host and report the real failure.

This logic is implemented so the response can still surface useful TLS data if the root host is dead but a real subdomain is alive.

### Returned fields
1. `subdomains_discovery.main_domain`
- The effective primary endpoint used for the scan summary.

2. `subdomains_discovery.main_domain_probe`
- The original root-domain probe result.

3. `subdomains_discovery.main_domain.resolved_from`
- Which hostname actually supplied the summary metrics.

## 10. Full Scan Payload Assembly

`scan_target(domain)` returns one merged dictionary with these major sections:

### Root scan fields
1. `main_domain`
2. `tls_version`
3. `tls_versions_list`
4. `cipher_suite`
5. `key_size`
6. `certificate_issuer`
7. `expiry_date`
8. `algorithm`
9. `days_to_expiry`
10. `ipv4`
11. `ipv6`

### Enrichment blocks
1. `vulnerabilities`
2. `hosting`
3. `mobile_info`

### Discovery blocks
1. `subdomains_discovery`
2. `subdomains_info`
3. `all_subdomains_detailed`
4. `active_subdomains`
5. `inactive_subdomains`
6. `pqc_ready_subdomains`
7. `standard_subdomains`
8. `critical_subdomains`

### Metadata
1. `scan_timestamp`
2. `full_scan = True`

## 11. Categorization Rules

Each discovered subdomain is bucketed after scanning:

### `pqc_ready`
Conditions:
1. Subdomain is active.
2. `days_to_expiry > 180`.
3. TLS 1.3 appears in the probed versions.

### `standard`
Conditions:
1. Subdomain is active.
2. `days_to_expiry > 90`.

### `critical`
Conditions:
1. Subdomain is inactive, or
2. It fails the thresholds above.

## 12. Risk Engine Logic

`calculate_advanced_risk(...)` in `backend/engines/risk_engine.py` is a weighted penalty model.

Inputs:
1. `tls_versions`
2. `algorithm`
3. `key_size`
4. `days_to_expiry`
5. `vulnerabilities`
6. `hosting`
7. `has_owner` defaulting to `True`
8. `pqc_kem_detected`
9. `pqc_status`

### Factor 1: Crypto risk

Rules:
1. RSA adds 60 points because it is quantum-risky.
2. ECC/ECDSA adds 30 points.
3. Weak RSA key sizes add more penalty.
4. Weak ECC sizes add more penalty.
5. Unknown algorithms with small keys also get penalized.

### Factor 2: Protocol risk

Rules:
1. Any legacy TLS 1.0/1.1 -> 100 risk.
2. TLS 1.2 + 1.3 together -> 60 risk.
3. TLS 1.2 only -> 50 risk.
4. TLS 1.3 only -> 0 risk.

### Factor 3: Vulnerability risk

Rules:
1. SQL injection or SQLI -> 100 risk.
2. XSS -> 50 risk.

### Factor 4: Exposure risk

Current implementation uses a flat 50.

### Factor 5: Third-party risk

Rules:
1. `hosting.type == "third_party"` -> 100 risk.
2. Otherwise -> 0 risk.

### Factor 6: Governance risk

Rules:
1. Missing owner -> 100 risk.
2. Owner present -> 0 risk.

### Final score

The final penalty is:

```text
0.30 * crypto_risk
0.20 * protocol_risk
0.20 * vuln_risk
0.10 * exposure_risk
0.10 * third_party_risk
0.10 * gov_risk
```

Then:

```text
score = max(0, 100 - total_penalty)
```

### PQC adjustments and post-rules

If PQC KEM is detected, the engine applies additional reductions before final score guards:
1. Full PQC: crypto `-45`, protocol `-20`
2. Hybrid PQC: crypto `-35`, protocol `-12`

After computing weighted score:
1. Full PQC score floor: minimum `72`
2. Hybrid PQC score floor: minimum `65`
3. Certificate expiry cap still applies last: if expired, score max is `10`

Certificate expiry override:
1. If `days_to_expiry < 0`, the score is capped at 10.

### Classification mapping

1. `score >= 80`
   - `category = Elite PQC`
   - `risk_level = Low`
   - `status = Secure`
   - `label = PQC Ready`

2. `score >= 60`
   - `category = Standard`
   - `risk_level = Medium`
   - `status = Partial`
   - `label = Quantum Safe`

3. `score >= 40`
   - `category = Transitional`
   - `risk_level = High`
   - `status = Vulnerable`
   - `label = Needs Upgrade`

4. Lower than 40
   - `category = Critical`
   - `risk_level = Critical`
   - `status = Vulnerable`
   - `label = Not Safe`

### Baseline score

The function also computes a baseline score for comparison:
1. `30` if the algorithm is legacy-safe bad enough.
2. `70` if TLS 1.2 is present.
3. `100` otherwise.

The `improvement` string is derived from the difference between baseline and current score.

## 13. Why Some Fields Say Unavailable

`Unavailable` is not a UI bug by itself. It usually means the network probe failed before a certificate could be read.

Common causes:
1. The root host does not answer HTTPS.
2. The server requires a different hostname and SNI.
3. The connection times out.
4. DNS resolves but the HTTPS service is absent.
5. The edge/CDN blocks the probe.

The important distinction is:
1. `Unknown` or `Unavailable` in raw scan data means the scanner could not verify the value.
2. Fallback values inside `risk_input` are only for scoring and should not be treated as proof that the host really supports that TLS version or algorithm.

## 14. What Is Real And What Is Mock

### Real network-backed behavior
1. DNS resolution.
2. crt.sh lookup.
3. TLS handshake probing.
4. Certificate parsing.
5. TLS version probing.

### Mock or synthetic behavior currently used
1. `discover_vulnerabilities(...)`
2. `discover_mobile_apps(...)`
3. `discover_vulnerabilities(...)` also fabricates hosting provider/type.

That means the scanner is real for discovery and TLS, but not all enrichment sources are production-grade yet.

## 15. Response Contract For The UI

The scanner UI relies on these exact response paths:

### Summary and risk
1. `risk.score`
2. `risk.score_pre_overrides`
3. `risk.total_penalty`
4. `risk.weights`
5. `risk.components`
6. `risk.adjustments`
7. `risk.formula_version`
8. `risk.risk_level`
9. `risk.status`
10. `risk.label`
11. `risk.category`

### Primary scan fields
1. `scan_result.tls_version`
2. `scan_result.cipher_suite`
3. `scan_result.key_size`
4. `scan_result.certificate_issuer`
5. `scan_result.expiry_date`
6. `scan_result.algorithm`
7. `scan_result.days_to_expiry`
8. `scan_result.ipv4`
9. `scan_result.ipv6`

### Subdomains
1. `scan_result.all_subdomains_detailed`
2. `scan_result.active_subdomains`
3. `scan_result.inactive_subdomains`
4. `scan_result.pqc_ready_subdomains`
5. `scan_result.standard_subdomains`
6. `scan_result.critical_subdomains`

If any of those keys change, the UI panels will degrade.

## 16. Debugging Checklist

If scanner output looks wrong, check in this order:
1. Confirm the backend is running on port 8010.
2. Call `POST /api/scan` with `example.com`.
3. If `example.com` is broken, the scanner code path is broken.
4. If `example.com` works and the target does not, the target is the issue or the first-pass certificate discovery timed out.
5. Inspect `subdomains_discovery.main_domain_probe.error`.
6. Inspect `subdomains_discovery.summary.discovery_sources`.
7. Inspect `subdomains_discovery.main_domain.resolved_from`.
8. Check whether the UI is using the right `VITE_API_URL`.

If a target still undercounts on the first scan, the next thing to improve is the discovery wordlist and the CRT retry budget, not the risk engine.

## 17. Current Known Constraints

1. The in-memory asset store resets on restart.
2. The common-prefix DNS list is finite.
3. crt.sh can be slow or incomplete.
4. Some domains only work on a subdomain, not on the root host.
5. Not every field is production-grade yet because some enrichment sources are still mock data.

## 18. Practical Reading Guide

If you want to understand the scanner from source code, read in this order:
1. `backend/engines/scanner.py`
2. `backend/main.py`
3. `backend/engines/risk_engine.py`
4. `src/components/Scanner.tsx`

If you follow those four files with this document, you should be able to explain:
1. how the domain is scanned,
2. how subdomains are discovered,
3. how TLS metrics are collected,
4. how the score is computed,
5. why some values are unavailable,
6. and exactly what the UI is rendering.
