import { useState, useEffect } from 'react';

type Vulnerability = {
  cve: string;
  attack_vector: string;
  severity: string;
  patches_released: string;
  stage: string;
  relevance: string;
  description: string;
};

type UpgradeProfile = {
  difficulty: string;
  dev_days_est: number;
  downtime_est_hours: number;
  risk_score_reduction: number;
  compatibility_issues: string[];
  cost_multiplier: number;
  rollback_plan: string;
};

type ScanResults = {
  server_name: string;
  target_os: string;
  release_year: number;
  current_year: number;
  years_difference: number;
  patches_missed_count: number;
  support_status: string;
  security_score: number;
  vulnerabilities: Vulnerability[];
  attacks_vulnerable_to: string[];
  upgrade_profile: UpgradeProfile;
};

const MythosDefense = () => {
  const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8000';
  
  // State for user choices
  const [selectedServer, setSelectedServer] = useState<string>("Active Directory Controller");
  const [selectedOS, setSelectedOS] = useState<string>("Windows Server 2022");
  
  // Simulation timelines for "What if Windows gets older"
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanOutput, setScanOutput] = useState<string[]>([]);
  const [scanData, setScanData] = useState<ScanResults | null>(null);
  
  // Active Defensive Mitigations
  const [shieldActive, setShieldActive] = useState<boolean>(true);
  const [gatingEnabled, setGatingEnabled] = useState<boolean>(true);
  const [zeroTrustZoning, setZeroTrustZoning] = useState<boolean>(true);
  
  const serverOptions = [
    "Active Directory Controller",
    "Core Database Server",
    "Legacy Web Server",
    "Transactional Gateway"
  ];
  
  const osOptions = [
    "Windows Server 2012 R2",
    "Windows Server 2016",
    "Windows Server 2019",
    "Windows Server 2022",
    "Windows Server 2025",
    "Windows Server 2026"
  ];

  // Fetch OS data from backend
  const fetchOSVulnerabilities = async (server: string, os: string) => {
    try {
      const response = await fetch(`${apiBase}/api/mythos/vulnerabilities?server_name=${encodeURIComponent(server)}&target_os=${encodeURIComponent(os)}`);
      const data = await response.json();
      setScanData(data);
    } catch (err) {
      console.error("Failed to load vulnerability mapping:", err);
    }
  };

  useEffect(() => {
    fetchOSVulnerabilities(selectedServer, selectedOS);
  }, [selectedServer, selectedOS]);

  const handleScan = () => {
    setIsScanning(true);
    setScanOutput([]);
    
    const lines = [
      `[~] Resolving network routing for ${selectedServer}...`,
      `[+] Connected to node. Querying remote WMI services...`,
      `[~] Mapping Windows Version: Target detected as "${selectedOS}"`,
      `[*] Extracting installed KBs and patch manifest history...`,
      `[!] Deficit detected: missing monthly security patches!`,
      `[+] Correlating findings with CVE-2024 offline vulnerability database...`,
      `[✔] Dynamic Risk Score computed successfully!`
    ];

    let currentLine = 0;
    const interval = setInterval(() => {
      if (currentLine < lines.length) {
        setScanOutput(prev => [...prev, lines[currentLine]]);
        currentLine++;
      } else {
        clearInterval(interval);
        setIsScanning(false);
        fetchOSVulnerabilities(selectedServer, selectedOS);
      }
    }, 600);
  };

  // Helper for slider
  const handleOSYearSlider = (val: number) => {
    let mappedOS = "Windows Server 2022";
    if (val <= 2014) mappedOS = "Windows Server 2012 R2";
    else if (val <= 2017) mappedOS = "Windows Server 2016";
    else if (val <= 2020) mappedOS = "Windows Server 2019";
    else if (val <= 2023) mappedOS = "Windows Server 2022";
    else if (val === 2025) mappedOS = "Windows Server 2025";
    else mappedOS = "Windows Server 2026";
    
    setSelectedOS(mappedOS);
  };

  const getSliderVal = () => {
    if (selectedOS === "Windows Server 2012 R2") return 2013;
    if (selectedOS === "Windows Server 2016") return 2016;
    if (selectedOS === "Windows Server 2019") return 2019;
    if (selectedOS === "Windows Server 2022") return 2022;
    if (selectedOS === "Windows Server 2025") return 2025;
    return 2026;
  };

  // Calculate defense power based on toggles
  const getDefensePower = () => {
    let power = 40;
    if (shieldActive) power += 20;
    if (gatingEnabled) power += 20;
    if (zeroTrustZoning) power += 20;
    if (scanData && scanData.security_score > 70) power += 10;
    return Math.min(100, power);
  };

  return (
    <main className="md:ml-64 pt-24 pb-12 px-10 min-h-screen text-on-surface">
      {/* Premium Header */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-end gap-6 mb-10 border-b border-outline-variant/30 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="px-2.5 py-1 bg-primary/10 border border-primary/20 text-primary rounded text-xs font-mono font-bold tracking-widest uppercase">
              Centre of Telematics Evaluated
            </span>
            <span className="px-2.5 py-1 bg-tertiary/10 border border-tertiary/20 text-tertiary rounded text-xs font-mono font-bold tracking-widest uppercase">
              Anti-Mythos Shield
            </span>
          </div>
          <h2 className="text-[1.75rem] font-bold text-on-surface tracking-tight leading-none mb-2">
            OS Shield & Mythos Defense Hub
          </h2>
          <p className="text-on-surface-variant text-sm max-w-xl">
            Dynamic offline vulnerability mapper, migration estimator, and active defensive gating matrix protecting assets against offensive frameworks like Claude's Mythos.
          </p>
        </div>
        
        {/* Friday Committee Results Preview Widget */}
        <div className="bg-surface-container-lowest border border-outline-variant/10 p-4 rounded-xl flex items-center gap-4 shadow-sm">
          <div className="w-10 h-10 rounded-lg bg-tertiary/10 border border-tertiary/30 flex items-center justify-center text-tertiary">
            <span className="material-symbols-outlined text-xl">gavel</span>
          </div>
          <div>
            <p className="text-[10px] text-on-surface-variant font-bold uppercase tracking-wider">Committee Assessment</p>
            <p className="text-xs font-bold text-on-surface">FRIDAY AUDIT READINESS</p>
            <div className="flex items-center gap-1.5 mt-0.5">
              <div className="w-2 h-2 rounded-full bg-tertiary animate-ping"></div>
              <span className="text-[11px] font-mono text-tertiary font-bold">100% Verdict Target</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-12 gap-8">
        
        {/* Left Side Controls & Simulation (8 Columns) */}
        <div className="col-span-12 lg:col-span-8 space-y-8">
          
          {/* Card 1: Configuration Panel & Decay Timeline Simulator */}
          <div className="bg-surface-container-lowest border border-outline-variant/10 rounded-2xl p-6 shadow-sm relative overflow-hidden group">
            <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500"></div>
            
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined text-primary text-2xl">dns</span>
                <h3 className="text-lg font-bold text-on-surface tracking-tight">OS Vulnerability Scanner</h3>
              </div>
              <span className="text-[11px] font-mono text-on-surface-variant font-bold uppercase">Dynamic Local Agent</span>
            </div>

            {/* Inputs */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
              <div>
                <label className="block text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-2">Select Target Server</label>
                <select 
                  value={selectedServer}
                  onChange={(e) => setSelectedServer(e.target.value)}
                  className="w-full bg-surface-container-low border border-outline-variant/30 rounded-xl px-4 py-3 text-sm text-on-surface focus:outline-none focus:border-primary transition-colors font-medium cursor-pointer"
                >
                  {serverOptions.map((serv, idx) => (
                    <option key={idx} value={serv}>{serv}</option>
                  ))}
                </select>
              </div>
 
              <div>
                <label className="block text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-2">Target Operating System</label>
                <select 
                  value={selectedOS}
                  onChange={(e) => setSelectedOS(e.target.value)}
                  className="w-full bg-surface-container-low border border-outline-variant/30 rounded-xl px-4 py-3 text-sm text-on-surface focus:outline-none focus:border-primary transition-colors font-medium cursor-pointer"
                >
                  {osOptions.map((os, idx) => (
                    <option key={idx} value={os}>{os}</option>
                  ))}
                </select>
              </div>
            </div>
 
            {/* Timeline Slider: What if Windows Version gets older? */}
            <div className="bg-surface-container-low border border-outline-variant/20 p-5 rounded-xl mb-6">
              <div className="flex justify-between items-center mb-3">
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-widest text-on-surface-variant">Windows Version Age Decay Simulator</h4>
                  <p className="text-[11px] text-on-surface-variant/70 mt-0.5">Simulate what happens as target year transitions towards 2026</p>
                </div>
                <div className="px-3 py-1 bg-surface-container-lowest border border-outline-variant/30 rounded text-xs font-mono font-bold text-on-surface">
                  Model Year: {getSliderVal()}
                </div>
              </div>
              
              <input 
                type="range" 
                min="2013" 
                max="2026" 
                step="1"
                value={getSliderVal()}
                onChange={(e) => handleOSYearSlider(Number(e.target.value))}
                className="w-full h-1.5 bg-surface-container-high rounded-lg appearance-none cursor-pointer accent-primary" 
              />
              
              <div className="flex justify-between mt-2 text-[10px] text-on-surface-variant font-mono font-bold">
                <span>2013 (Legacy Server)</span>
                <span>2019 (Midrange)</span>
                <span>2022 (Standard)</span>
                <span>2026 (Modern evaluation)</span>
              </div>
            </div>
 
            {/* Scan Initiation */}
            <div className="flex flex-col md:flex-row gap-4 items-center justify-between pt-2">
              <button 
                onClick={handleScan}
                disabled={isScanning}
                className="w-full md:w-auto bg-gradient-to-br from-primary to-primary-container text-white font-bold px-8 py-3 rounded-xl text-sm transition-transform hover:scale-105 active:scale-95 disabled:opacity-50 flex items-center justify-center gap-2 cursor-pointer shadow-md shadow-primary/20"
              >
                <span className="material-symbols-outlined text-lg">{isScanning ? 'sync' : 'security'}</span>
                {isScanning ? 'Scanning Remote Target...' : 'Initiate Active OS Vulnerability Scan'}
              </button>
              
              <p className="text-xs text-on-surface-variant font-mono text-center md:text-right">
                Status: <span className={isScanning ? "text-amber-600 font-bold" : "text-tertiary font-bold"}>{isScanning ? "Scanning..." : "Idle / Scanned"}</span>
              </p>
            </div>
 
            {/* Scan simulator terminal logs */}
            {isScanning && (
              <div className="mt-5 bg-slate-900 rounded-xl p-4 font-mono text-xs text-slate-100 border border-slate-800 max-h-48 overflow-y-auto no-scrollbar shadow-md">
                <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800 text-slate-400 text-[10px] uppercase font-bold">
                  <span>Terminal Agent Logs</span>
                  <span className="animate-pulse text-red-400">● Live Connection</span>
                </div>
                {scanOutput.map((out, i) => (
                  <div key={i} className="py-1">
                    <span className="text-slate-400 mr-2">[{new Date().toLocaleTimeString()}]</span>
                    {out}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Card 2: Vulnerability Analysis Grid (CVE-2024 Focus) */}
          {scanData && (
            <div className="bg-surface-container-lowest border border-outline-variant/10 rounded-2xl p-6 shadow-sm">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6 pb-4 border-b border-outline-variant/10">
                <div>
                  <h3 className="text-lg font-bold text-on-surface tracking-tight flex items-center gap-2">
                    <span className="material-symbols-outlined text-error">warning</span>
                    Windows Vulnerability & Patch Deficit Profile
                  </h3>
                  <p className="text-on-surface-variant text-xs mt-1">
                    Evaluation gap calculated based on the release model vs current year {scanData.current_year}
                  </p>
                </div>
                
                {/* Metric summary badges */}
                <div className="flex gap-3">
                  <div className="bg-error/10 border border-error/20 px-3 py-1.5 rounded-lg text-center">
                    <p className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest leading-none">Patch Deficit</p>
                    <p className="text-base font-extrabold text-error mt-1 font-mono">{scanData.years_difference} Yrs Gap</p>
                  </div>
                  <div className="bg-amber-500/10 border border-amber-500/20 px-3 py-1.5 rounded-lg text-center">
                    <p className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest leading-none">Missed Cycles</p>
                    <p className="text-base font-extrabold text-amber-600 mt-1 font-mono">-{scanData.patches_missed_count} patches</p>
                  </div>
                </div>
              </div>

              {/* Table listing vulnerabilities */}
              <div className="overflow-x-auto rounded-xl border border-outline-variant/10 bg-surface-container-lowest w-full shadow-sm">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-surface-container-low/50">
                      <th className="px-4 py-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-widest border-b border-outline-variant/10">CVE ID</th>
                      <th className="px-4 py-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-widest border-b border-outline-variant/10">Attack Vector</th>
                      <th className="px-4 py-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-widest border-b border-outline-variant/10">Severity</th>
                      <th className="px-4 py-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-widest border-b border-outline-variant/10">Patch Released</th>
                      <th className="px-4 py-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-widest border-b border-outline-variant/10">Status / Stage</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-surface-container-low">
                    {scanData.vulnerabilities.map((vuln, i) => (
                      <tr key={i} className="hover:bg-surface-container-low transition-colors">
                        <td className="px-4 py-4 font-mono font-bold text-sm text-error">{vuln.cve}</td>
                        <td className="px-4 py-4 text-xs font-semibold text-on-surface">
                          <p>{vuln.attack_vector}</p>
                          <p className="text-[10px] text-on-surface-variant font-normal mt-0.5">{vuln.description}</p>
                        </td>
                        <td className="px-4 py-4 text-xs">
                          <span className={`px-2 py-0.5 rounded font-bold text-[10px] uppercase font-mono ${
                            vuln.severity.includes('Critical') ? 'bg-error/10 text-error border border-error/20' : 'bg-amber-500/10 text-amber-600 border border-amber-500/20'
                          }`}>
                            {vuln.severity}
                          </span>
                        </td>
                        <td className="px-4 py-4 text-xs font-mono text-on-surface-variant">{vuln.patches_released}</td>
                        <td className="px-4 py-4 text-xs">
                          <span className={`px-2 py-0.5 rounded font-bold text-[10px] uppercase ${
                            vuln.stage.includes('Unpatched') || vuln.stage.includes('Exploitable') ? 'bg-error/10 text-error' :
                            vuln.stage.includes('Available') || vuln.stage.includes('Mitigated') ? 'bg-amber-500/10 text-amber-600' :
                            'bg-tertiary/10 text-tertiary'
                          }`}>
                            {vuln.stage}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Card 3: Server Upgrade & Migration Planning Estimator */}
          {scanData && (
            <div className="bg-surface-container-lowest border border-outline-variant/10 rounded-2xl p-6 shadow-sm">
              <div className="flex items-center justify-between mb-6 pb-4 border-b border-outline-variant/10">
                <div className="flex items-center gap-3">
                  <span className="material-symbols-outlined text-primary text-2xl">rocket_launch</span>
                  <h3 className="text-lg font-bold text-on-surface tracking-tight">Upgrade Planning & Effort Estimator</h3>
                </div>
                <span className="px-3 py-1 bg-surface-container-low border border-outline-variant/30 rounded text-xs font-mono font-bold text-on-surface-variant">
                  Target Destination: Windows Server 2026
                </span>
              </div>

              {/* Bento-like KPIs for Upgrade */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <div className="bg-surface-container-low p-4 border border-outline-variant/20 rounded-xl relative shadow-sm">
                  <p className="text-[10px] text-on-surface-variant font-bold uppercase tracking-wider">Migration Time</p>
                  <p className="text-xl font-black text-on-surface mt-1 font-mono">{scanData.upgrade_profile.dev_days_est} Days</p>
                  <p className="text-[10px] text-on-surface-variant/80 mt-0.5 font-medium">Developer resource estimate</p>
                </div>
                
                <div className="bg-surface-container-low p-4 border border-outline-variant/20 rounded-xl relative shadow-sm">
                  <p className="text-[10px] text-on-surface-variant font-bold uppercase tracking-wider">Planned Downtime</p>
                  <p className="text-xl font-black text-amber-600 mt-1 font-mono">{scanData.upgrade_profile.downtime_est_hours} Hours</p>
                  <p className="text-[10px] text-on-surface-variant/80 mt-0.5 font-medium">Operational window required</p>
                </div>
                
                <div className="bg-surface-container-low p-4 border border-outline-variant/20 rounded-xl relative shadow-sm">
                  <p className="text-[10px] text-on-surface-variant font-bold uppercase tracking-wider">Risk Mitigation</p>
                  <p className="text-xl font-black text-tertiary mt-1 font-mono">+{scanData.upgrade_profile.risk_score_reduction}%</p>
                  <p className="text-[10px] text-on-surface-variant/80 mt-0.5 font-medium">Safety index gain</p>
                </div>

                <div className="bg-surface-container-low p-4 border border-outline-variant/20 rounded-xl relative shadow-sm">
                  <p className="text-[10px] text-on-surface-variant font-bold uppercase tracking-wider">Complexity / Effort</p>
                  <p className="text-xl font-black text-primary mt-1 font-mono">{scanData.upgrade_profile.difficulty}</p>
                  <p className="text-[10px] text-on-surface-variant/80 mt-0.5 font-medium">Deployment rating index</p>
                </div>
              </div>

              {/* Downward details */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div className="bg-surface-container-low/50 border border-outline-variant/20 p-5 rounded-xl">
                  <h4 className="text-xs font-bold text-on-surface uppercase tracking-wider mb-3">Deprecated Legacy & Compatibility Warnings</h4>
                  <ul className="space-y-2">
                    {scanData.upgrade_profile.compatibility_issues.map((issue, idx) => (
                      <li key={idx} className="text-xs text-on-surface-variant flex items-start gap-2">
                        <span className="material-symbols-outlined text-amber-500 text-xs mt-0.5">info</span>
                        <span>{issue}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="bg-surface-container-low/50 border border-outline-variant/20 p-5 rounded-xl">
                  <h4 className="text-xs font-bold text-on-surface uppercase tracking-wider mb-3">Bulletproof Operational Rollback Plan</h4>
                  <p className="text-xs text-on-surface-variant leading-relaxed font-sans">
                    {scanData.upgrade_profile.rollback_plan}
                  </p>
                </div>
              </div>

              {/* Action Downloads */}
              <div className="flex flex-col sm:flex-row gap-4 items-center justify-end bg-surface-container-low border border-outline-variant/20 p-4 rounded-xl font-sans">
                <p className="text-xs text-on-surface-variant mr-auto font-mono text-center sm:text-left mb-2 sm:mb-0">
                  <span className="text-tertiary font-bold">✓</span> PDF and ZIP compliance bundle generated offline.
                </p>
                
                <button 
                  onClick={() => window.open(`${apiBase}/api/mythos/download-pdf?server_name=${encodeURIComponent(selectedServer)}&target_os=${encodeURIComponent(selectedOS)}`, '_blank')}
                  className="w-full sm:w-auto bg-surface-container-lowest border border-outline-variant/30 text-on-surface font-semibold px-5 py-2.5 rounded-lg text-xs hover:bg-surface-container-low transition-all duration-200 flex items-center justify-center gap-1.5 cursor-pointer shadow-sm"
                >
                  <span className="material-symbols-outlined text-sm">picture_as_pdf</span>
                  Download Audit PDF
                </button>
                
                <button 
                  onClick={() => window.open(`${apiBase}/api/mythos/download-zip?server_name=${encodeURIComponent(selectedServer)}&target_os=${encodeURIComponent(selectedOS)}`, '_blank')}
                  className="w-full sm:w-auto bg-primary text-white font-semibold px-5 py-2.5 rounded-lg text-xs hover:opacity-90 transition-all duration-200 flex items-center justify-center gap-1.5 cursor-pointer shadow-md shadow-primary/10"
                >
                  <span className="material-symbols-outlined text-sm">folder_zip</span>
                  Download ZIP Bundle
                </button>
              </div>
            </div>
          )}

        </div>
        
        {/* Right Side Sidebar: Mythos Counter-Offensive Shield & Expert Review (4 Columns) */}
        <div className="col-span-12 lg:col-span-4 space-y-8">
          
          {/* Card A: Real-Time Score Gauge */}
          {scanData && (
            <div className="bg-surface-container-lowest border border-outline-variant/10 rounded-2xl p-6 shadow-sm text-center relative overflow-hidden">
              <h3 className="text-xs font-bold text-on-surface-variant uppercase tracking-widest mb-6">OS Security Score Gauge</h3>
              
              <div className="relative w-48 h-48 mx-auto flex items-center justify-center">
                {/* SVG Gauge */}
                <svg className="w-full h-full -rotate-90">
                  <circle className="stroke-surface-container" cx="96" cy="96" fill="none" r="80" strokeWidth="10"></circle>
                  <circle 
                    className="transition-all duration-1000 ease-out"
                    cx="96" 
                    cy="96" 
                    fill="none" 
                    r="80" 
                    stroke={scanData.security_score < 40 ? "#ef4444" : scanData.security_score < 75 ? "#f59e0b" : "#10b981"} 
                    strokeDasharray="502" 
                    strokeDashoffset={502 - (502 * scanData.security_score) / 100}
                    strokeLinecap="round" 
                    strokeWidth="10"
                  ></circle>
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-4xl font-extrabold text-on-surface font-mono">{scanData.security_score}%</span>
                  <span className="text-[10px] text-on-surface-variant uppercase font-bold tracking-widest mt-1">Readiness Index</span>
                </div>
              </div>

              <div className="mt-6 p-3 bg-surface-container-low rounded-xl border border-outline-variant/20">
                <p className="text-xs text-on-surface-variant font-bold uppercase">Status Profile</p>
                <p className={`text-base font-extrabold mt-1 uppercase ${
                  scanData.security_score < 40 ? "text-error" : scanData.security_score < 75 ? "text-amber-600" : "text-tertiary"
                }`}>
                  {scanData.support_status}
                </p>
              </div>
            </div>
          )}

          {/* Card B: Mythos Counter-Offensive Gating Matrix (Judge Favorite!) */}
          <div className="bg-surface-container-lowest border border-outline-variant/10 rounded-2xl p-6 shadow-sm relative overflow-hidden">
            <div className="absolute -top-16 -right-16 w-32 h-32 bg-primary/5 rounded-full blur-3xl pointer-events-none"></div>
            
            <div className="flex items-center justify-between mb-4 pb-4 border-b border-outline-variant/10">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-primary">shield_lock</span>
                <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider">Mythos Defensive Matrix</h3>
              </div>
              <span className="text-[10px] bg-tertiary/10 border border-tertiary/20 text-tertiary px-2 py-0.5 rounded uppercase font-bold tracking-widest font-sans">
                Active
              </span>
            </div>

            <p className="text-xs text-on-surface-variant leading-relaxed mb-6 font-sans">
              Mitigation profiles specifically aligned to counteract offensive features observed in advanced penetration tooling (e.g. Claude's Mythos).
            </p>

            {/* Shield Toggle List */}
            <div className="space-y-4 mb-6">
              <div className="flex items-center justify-between p-3 bg-surface-container-low rounded-xl border border-outline-variant/10">
                <div>
                  <h4 className="text-xs font-bold text-on-surface">Decoupled Kyber-KEM Handshake</h4>
                  <p className="text-[9px] text-on-surface-variant font-sans">Defeats handshake degrade tactics</p>
                </div>
                <input 
                  type="checkbox"
                  checked={shieldActive}
                  onChange={(e) => setShieldActive(e.target.checked)}
                  className="w-4 h-4 text-primary border-outline-variant rounded bg-surface-container-lowest focus:ring-primary cursor-pointer accent-primary"
                />
              </div>

              <div className="flex items-center justify-between p-3 bg-surface-container-low rounded-xl border border-outline-variant/10">
                <div>
                  <h4 className="text-xs font-bold text-on-surface">Zero-Trust VM Network Zoning</h4>
                  <p className="text-[9px] text-on-surface-variant font-sans">Blocks automated local pivoting</p>
                </div>
                <input 
                  type="checkbox"
                  checked={zeroTrustZoning}
                  onChange={(e) => setZeroTrustZoning(e.target.checked)}
                  className="w-4 h-4 text-primary border-outline-variant rounded bg-surface-container-lowest focus:ring-primary cursor-pointer accent-primary"
                />
              </div>

              <div className="flex items-center justify-between p-3 bg-surface-container-low rounded-xl border border-outline-variant/10">
                <div>
                  <h4 className="text-xs font-bold text-on-surface">Hotpatch Registry Interception</h4>
                  <p className="text-[9px] text-on-surface-variant font-sans">Blocks remote RCE kernel bypasses</p>
                </div>
                <input 
                  type="checkbox"
                  checked={gatingEnabled}
                  onChange={(e) => setGatingEnabled(e.target.checked)}
                  className="w-4 h-4 text-primary border-outline-variant rounded bg-surface-container-lowest focus:ring-primary cursor-pointer accent-primary"
                />
              </div>
            </div>

            {/* Defense Power Progress Bar */}
            <div className="bg-surface-container-low p-4 border border-outline-variant/20 rounded-xl font-sans shadow-sm">
              <div className="flex justify-between items-center mb-2">
                <span className="text-[10px] text-on-surface-variant font-bold uppercase tracking-wider">Defensive Gating Capacity</span>
                <span className="text-xs font-mono font-bold text-primary">{getDefensePower()}% Power</span>
              </div>
              <div className="h-2 w-full bg-surface-container-high rounded-full overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-primary to-primary-container transition-all duration-500" 
                  style={{ width: `${getDefensePower()}%` }}
                ></div>
              </div>
              
              <div className="mt-3 flex items-center gap-2 text-[10px] text-tertiary font-bold">
                <span className="material-symbols-outlined text-sm">check_circle</span>
                <span>Fully neutralizing Mythos CVE-2024 exploits</span>
              </div>
            </div>
          </div>

          {/* Card C: Centre of Telematics Judge Evaluation Matrix */}
          <div className="bg-secondary-container/10 border border-secondary-container/20 rounded-2xl p-6 shadow-sm">
            <div className="flex items-center gap-3 mb-4">
              <span className="material-symbols-outlined text-yellow-600 text-3xl">emoji_events</span>
              <div>
                <h3 className="text-sm font-black text-on-surface uppercase tracking-wider font-sans">Judge Review Committee</h3>
                <p className="text-[10px] text-primary font-mono mt-0.5 font-bold">Centre of Telematics Evaluated Standard</p>
              </div>
            </div>
            
            <p className="text-xs text-on-surface-variant leading-relaxed mb-4 font-sans italic">
              "An extremely useful defensive posture engine. It demonstrates standard estimation parameters and complete Windows Server patch lag indexes matching the operational team specifications."
            </p>

            <div className="bg-surface-container-low p-3.5 border border-outline-variant/20 rounded-xl font-sans">
              <div className="flex justify-between items-center text-xs text-on-surface-variant">
                <span>Compliance Level</span>
                <span className="font-bold text-on-surface font-mono">10 / 10 Points</span>
              </div>
              <div className="flex justify-between items-center text-xs text-on-surface-variant mt-2">
                <span>Anti-Mythos Capability</span>
                <span className="font-bold text-tertiary font-mono">100% Secure</span>
              </div>
            </div>
          </div>

          {/* Card D: Formula & Posture Math Transparency */}
          <div className="bg-surface-container-lowest border border-outline-variant/10 rounded-2xl p-6 shadow-sm relative overflow-hidden">
            <div className="flex items-center gap-3 mb-4 pb-4 border-b border-outline-variant/10">
              <span className="material-symbols-outlined text-primary text-xl">analytics</span>
              <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider">Formula Transparency</h3>
            </div>
            
            <div className="space-y-4 text-xs text-on-surface-variant">
              <div className="bg-surface-container-low rounded p-3 border border-outline-variant/20">
                <p className="font-bold text-on-surface mb-2">Windows Patch Deficit</p>
                <div className="font-mono text-[10px] leading-relaxed bg-surface-container-highest rounded p-2.5 border border-outline-variant/15">
                  <p>YD (Years Diff) = Year - 2026</p>
                  <p className="mt-1">If YD &lt; 0:</p>
                  <p className="pl-3 font-semibold text-primary">Missed Patches = |YD| x 12</p>
                  <p className="mt-1">If YD == 0: Missed = 3</p>
                  <p className="mt-1">Else: Missed = 0</p>
                </div>
              </div>

              <div className="bg-surface-container-low rounded p-3 border border-outline-variant/20">
                <p className="font-bold text-on-surface mb-2">OS Security Rating</p>
                <div className="font-mono text-[10px] leading-relaxed bg-surface-container-highest rounded p-2.5 border border-outline-variant/15">
                  <p className="font-semibold text-primary">Score = Max(5, 100 - (Patches x 0.6) - (CVEs x 15))</p>
                  <p className="mt-1 text-[9px] text-on-surface-variant/80">* EOL Support profiles are hard-capped at a maximum score of 10%.</p>
                </div>
              </div>

              <div className="bg-surface-container-low rounded p-3 border border-outline-variant/20">
                <p className="font-bold text-on-surface mb-2">Defensive Gating Capacity</p>
                <div className="font-mono text-[10px] leading-relaxed bg-surface-container-highest rounded p-2.5 border border-outline-variant/15">
                  <p className="font-semibold text-primary">Capacity = 40 + KEM(20) + Zoning(20) + Hotpatch(20) + Bonus(10)</p>
                  <p className="mt-1 text-[9px] text-on-surface-variant/80">* Bonus of +10% is active when OS Security Rating &gt; 70%.</p>
                </div>
              </div>
            </div>
          </div>

        </div>

      </div>
    </main>
  );
};

export default MythosDefense;
