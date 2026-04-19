<div align="center">

# 🛡️ Quantum Shield: Enterprise Post-Quantum Security Platform

  **The ultimate real-time cryptographic scanner and AI-driven post-quantum readiness engine.**
  <br>
  *Built by Team - CyberRiot*
  
  <br>

  [![Hackathon](https://img.shields.io/badge/Event-PNB_Hackathon-0050cb?style=for-the-badge&logo=codeforces)](#)
  [![Security](https://img.shields.io/badge/Security-NIST_PQC_Compliant-10b981?style=for-the-badge&logo=shield)](#)
  [![Architecture](https://img.shields.io/badge/Architecture-FastAPI_%7C_React-black?style=for-the-badge&logo=python)](#)
  
  <br>
  
  <img src="src/assets/scanner.png" alt="Quantum Shield Scanner Interface" width="100%" style="border-radius: 12px; margin-top: 15px; margin-bottom: 20px; box-shadow: 0 4px 24px rgba(0,0,0,0.1);" />
  
</div>

---

## ⚡ The Cryptographic Apocalypse
In the impending era of Cryptographically Relevant Quantum Computers (CRQCs), Shor’s algorithm will fundamentally break RSA, ECC, and Diffie-Hellman encryption. **Confidentiality and integrity**—the core pillars of global cybersecurity—are at critical risk of "Harvest Now, Decrypt Later" attacks. If enterprise data is intercepted today, it will be decrypted tomorrow.

## 💡 The Quantum Shield Solution
**Crazy crazy stuff we have made.** Quantum Shield is not just a tool; it's an unprecedented, fully automated enterprise nervous system. We built a platform that actively crawls massive enterprise networks, dissecting deep binary SSL/TLS handshakes in real-time. It maps your entire Cryptographic Bill of Materials (CBOM) and strictly evaluates every node against NIST’s upcoming post-quantum standards (Kyber/Dilithium).

Your enterprise’s **confidentiality and integrity** are actively preserved through beautiful, real-time dashboards and aggressive generative AI automation.

---

## 🚀 Jaw-Dropping Features

### 🔍 Real-Time Deep Cryptographic Scanning & CBOM Generation
Quantum Shield doesn't rely on cached data. Our advanced Python backend manually opens TCP socket streams to target infrastructure, pulling raw cryptographic metadata to build a massive **Cryptographic Bill of Materials (CBOM)**. It detects:
*   The exact **TLS implementation version**.
*   The full **Cipher Suite & Key Lengths** negotiated.
*   The raw algorithm profile (RSA, ECDSA) to calculate a deterministic **Quantum Risk Score**.
*   Any impending certificate expirations that could result in devastating outages.

#### 🧮 Scoring Logic & Criticality Definition (Prototype)
Our integrated Risk Engine deterministically calculates the severity and criticality of scanned assets based on a strict 100-point metric system. Factors defining the risk exposure include:

*   **Protocol & Transport (max 35 pts):** TLS 1.3 (+35) vs legacy TLS 1.2 (+20) or outdated TLS 1.1/1.0.
*   **Cryptographic Algorithm (max 35 pts):** PQC-resistant symmetric ciphers like AES/ChaCha (+35), ECC/ECDSA (+20), and legacy asymmetric like RSA (+5).
*   **Key Size Strength (max 30 pts):** Robust >= 4096-bit (+30) vs standard 2048-bit (+15) vs extremely weak < 2048-bit (+0).
*   **Operational Penalties:** Assets with certificates expiring within 30 days receive a severe point reduction (-20). Fully expired certificates automatically cap the overall score at **10 (Critical failure)**.

**Risk Severity Categorization:**
1.  **Low Risk (Score ≥ 85):** Asset is utilizing modern transport (TLS 1.3) with perfect forward secrecy and quantum-resistant key lengths. Graded as **PQC Ready**.
2.  **Medium Risk (Score 50 - 84):** Typical of standard AES/ECC 2048-bit implementations. Graded as **Partial**. *(Note: Any asset running RSA algorithms is strictly clamped to a minimum of Medium risk regardless of key size due to Shor's algorithm vulnerability).*
3.  **High Risk (Score < 50):** Critical vulnerabilities. The asset utilizes deprecated TLS, extremely weak key lengths, or expired certificates. Immediate remediation is required. Graded as **Vulnerable / Not Safe**.

### 🤖 Precise Sentinel AI (Generative NLP Chatbot)
<div align="center">
  <img src="src/assets/chatbot.png" alt="Quantum AI Chatbot Interface" width="90%" style="border-radius: 8px; margin: 15px 0; border: 1px solid #e2e8f0; box-shadow: 0 4px 12px rgba(0,0,0,0.05);" />
</div>

Why click through 50 menus when you can literally just **tell your infrastructure what to do?** We integrated Google’s Gemini foundation model natively into our control center.
*   **Fully Automated Scan Scheduling:** Just type *"Schedule check for internal.com every week at 3 PM"* and the AI natively accesses the internal Python Cron engine to schedule and queue the job indefinitely.
*   **Automated Email Scheduling & Dispatch:** Type *"Email the risk report to ceo@bank.com"* and the AI will assemble a beautiful, contextual PDF, generate a C-Suite executive summary, and dispatch it via SMTP—all autonomously.

### 📑 Dynamic Executive PDF Reporting
<div align="center">
  <img src="src/assets/report.png" alt="Executive Vulnerability Report" width="90%" style="border-radius: 8px; margin: 15px 0; border: 1px solid #e2e8f0; box-shadow: 0 4px 12px rgba(0,0,0,0.05);" />
</div>

Information is useless if board members cannot understand it. We implemented a completely dynamic **ReportLab Engine** that generates executive disclosures on-the-fly.
*   **Master Inventories:** Sleek, midnight-blue themed PDF generation of every endpoint your company operates.
*   **Critical Vulnerability Disclosures:** Extracts *only* the failing algorithms (e.g., RSA-2048) and highlights them in aggressive crimson-red tables, demanding immediate remediation signatures from Executives.

### 🔐 Multi-Layered Threat Defense & Interactive Dashboards
*   **2x Authentication (2FA) Implementation:** We integrated robust Two-Factor OTP authentication out of the gate to ensure that only cleared personnel can trigger deep network scans or view cryptographic vulnerabilities.
*   **Risk Heatmaps & Graph Visualization:** Instead of raw JSON, network topologies are visualized through interactive Node-Edge network graphs and dense heatmap matrices tracking historical risk exposure.
*   **Auto-Scheduling UI Buttons:** You don't have to use the AI to automate tasks. We built direct 1-click Auto Schedule buttons directly into the scanner grid.

---

## 🏗️ Technical Architecture

We spared absolutely no expense building a modern, highly concurrent stack:
*   **Frontend (Vercel-Ready):** React 18, Vite, TypeScript, and a fully custom Tailwind CSS design system simulating extreme, premium modern B2B SaaS aesthetics (glassmorphism, bento grids, micro-animations).
*   **Backend (Engine):** Low-latency Python FastAPI handling deep socket resolutions.
*   **AI Core:** Gemini 1.5 Flash API for intent resolution and summary compilation.
*   **Reporting:** ReportLab for native PDF rendering on-the-fly.

---

## 🏁 How to Run

1. **Install Dependencies:**
   ```bash
   # Frontend
   npm install
   
   # Backend
   cd backend
   pip install -r requirements.txt
   ```

2. **Start the Systems:**
   *First Terminal (Backend):*
   ```bash
   cd backend
   uvicorn main:app --reload --port 8000
   ```
   *Second Terminal (Frontend):*
   ```bash
   npm run dev
   ```

---

*“To defend against the cryptography of tomorrow, you must adapt today.”*

<br><br><br>
<p align="center">
  <small>Open Source initiative by <b>Team - CyberRiot</b> for the PNB Hackathon</small>
</p>
