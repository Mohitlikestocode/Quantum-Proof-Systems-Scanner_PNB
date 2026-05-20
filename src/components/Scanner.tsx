import { useEffect, useMemo, useState } from 'react';

const Scanner = () => {
  const [target, setTarget] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [showToast, setShowToast] = useState(false);
  const [toastMsg, setToastMsg] = useState("");
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'inactive'>('all');
  const [bucketFilter, setBucketFilter] = useState<'all' | 'pqc_ready' | 'standard' | 'critical'>('all');
  const [subdomainQuery, setSubdomainQuery] = useState('');
  const [subdomainPage, setSubdomainPage] = useState(0);
  const [scheduleFrequency, setScheduleFrequency] = useState<'daily' | 'weekly' | 'monthly'>('daily');
  const [scheduleTime, setScheduleTime] = useState('02:00');
  const [scheduleDayOfWeek, setScheduleDayOfWeek] = useState('mon');
  const [scheduleDayOfMonth, setScheduleDayOfMonth] = useState(1);
  const [scheduleEmail, setScheduleEmail] = useState(localStorage.getItem('userEmail') || 'admin@quantumshield.local');
  const [isScheduling, setIsScheduling] = useState(false);
  const [scanMode, setScanMode] = useState<'Full Deep Scan' | 'Quick Scan'>('Full Deep Scan');
  const role = localStorage.getItem('userRole') || 'User';
  const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  const mobileApps = useMemo(() => scanResult?.scan_result?.mobile_info?.apps || [], [scanResult]);
  const topMobileMatch = scanResult?.scan_result?.mobile_info?.most_relevant_app;

  const keyExchangeLabel = useMemo(() => {
    const kem = scanResult?.scan_result?.pqc_kem_algorithm;
    if (!kem) return scanResult?.scan_result?.algorithm || '---';
    if (String(kem).toUpperCase().includes('MLKEM')) {
      return `${kem} (Kyber Family)`;
    }
    return kem;
  }, [scanResult]);

  const scanPerformance = useMemo(() => {
    const result = scanResult?.scan_result || {};
    const responseMs = Number(result?.response_time_ms || 0);
    const shownDuration = responseMs > 0 ? `${(responseMs / 1000).toFixed(2)}s` : (scanResult ? 'N/A' : '---');
    const subdomainCount = Number(result?.all_subdomains_detailed?.length || 0);
    const vulnTargets = Number(result?.vulnerability_scan?.scan_targets || 0);
    return {
      duration: shownDuration,
      payloads: subdomainCount + vulnTargets,
    };
  }, [scanResult]);

  const riskWeights = scanResult?.risk?.weights || {
    crypto: 0.3,
    protocol: 0.2,
    vulnerability: 0.2,
    exposure: 0.1,
    third_party: 0.1,
    governance: 0.1,
  };

  const riskComponents = scanResult?.risk?.components || {
    crypto: 0,
    protocol: 0,
    vulnerability: 0,
    exposure: 0,
    third_party: 0,
    governance: 0,
  };

  const riskRows = [
    { key: 'crypto', label: 'Crypto' },
    { key: 'protocol', label: 'Protocol' },
    { key: 'vulnerability', label: 'Vulnerability' },
    { key: 'exposure', label: 'Exposure' },
    { key: 'third_party', label: 'Third-Party' },
    { key: 'governance', label: 'Governance' },
  ];

  const riskContributionRows = riskRows.map((row) => {
    const factorValue = Number(riskComponents?.[row.key] || 0);
    const weight = Number(riskWeights?.[row.key] || 0);
    return {
      ...row,
      factorValue,
      weight,
      contribution: Number((factorValue * weight).toFixed(2)),
    };
  });

  const computedPenalty = Number(
    riskContributionRows.reduce((sum, row) => sum + row.contribution, 0).toFixed(2)
  );

  const subdomainRows = useMemo(() => {
    const rows = scanResult?.scan_result?.all_subdomains_detailed || [];
    return rows.map((row: any) => {
      const days = row?.days_to_expiry;
      let bucket = 'critical';
      if (typeof days === 'number' && days > 180) bucket = 'pqc_ready';
      else if (typeof days === 'number' && days > 90) bucket = 'standard';

      return {
        ...row,
        bucket,
      };
    });
  }, [scanResult]);

  const filteredSubdomainRows = useMemo(() => {
    return subdomainRows.filter((row: any) => {
      const matchesStatus = statusFilter === 'all' || row.status === statusFilter;
      const matchesBucket = bucketFilter === 'all' || row.bucket === bucketFilter;
      const matchesQuery = !subdomainQuery.trim() || String(row.subdomain || '').toLowerCase().includes(subdomainQuery.toLowerCase());
      return matchesStatus && matchesBucket && matchesQuery;
    });
  }, [subdomainRows, statusFilter, bucketFilter, subdomainQuery]);

  const subdomainPageSize = 10;
  const subdomainPageCount = Math.max(1, Math.ceil(filteredSubdomainRows.length / subdomainPageSize));
  const pagedSubdomainRows = useMemo(() => {
    const start = subdomainPage * subdomainPageSize;
    return filteredSubdomainRows.slice(start, start + subdomainPageSize);
  }, [filteredSubdomainRows, subdomainPage]);

  useEffect(() => {
    setSubdomainPage(0);
  }, [scanResult, statusFilter, bucketFilter, subdomainQuery]);



  const handshakeStatus = useMemo(() => {
    const discovery = scanResult?.scan_result?.subdomains_discovery;
    const mainProbe = discovery?.main_domain;
    const rootProbe = discovery?.main_domain_probe;

    if (!scanResult) {
      return {
        label: 'TLS handshake not started',
        detail: 'Run a scan to probe TLS handshake status',
        dotClass: 'bg-slate-400',
      };
    }

    if (mainProbe?.connection_successful) {
      const endpoint = mainProbe?.resolved_from || scanResult?.name || 'target host';
      return {
        label: 'TLS handshake successful',
        detail: `Endpoint: ${endpoint}`,
        dotClass: 'bg-emerald-500',
      };
    }

    const errorMsg = mainProbe?.error || rootProbe?.error || 'Handshake failed or timed out';
    return {
      label: 'TLS handshake attempted but failed',
      detail: errorMsg,
      dotClass: 'bg-red-500',
    };
  }, [scanResult]);

  const handleScan = async () => {
    if (!target) return;
    setIsScanning(true);
    try {
      const res = await fetch(apiBase + '/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': role
        },
        body: JSON.stringify({ domain: target, mode: scanMode })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.detail || `Scan request failed with status ${res.status}`);
      }

      setScanResult(data);
      setToastMsg(`Scan Completed: ${target}`);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 4000);
    } catch (err: any) {
      console.error("Scan request error", err);
      const errorMessage = err?.message || 'Unable to reach scanner service';
      setToastMsg(`Unable to complete scan for ${target}: ${errorMessage}`);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 4000);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSchedule = async () => {
    if (!target.trim()) {
      setToastMsg('Enter target domain before scheduling scans.');
      setShowToast(true);
      setTimeout(() => setShowToast(false), 4000);
      return;
    }

    setIsScheduling(true);
    try {
      const res = await fetch(apiBase + '/api/schedule', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': role,
        },
        body: JSON.stringify({
          frequency: scheduleFrequency,
          time: scheduleTime,
          domain: target.trim(),
          email: scheduleEmail.trim() || 'admin@quantumshield.local',
          day_of_week: scheduleFrequency === 'weekly' ? scheduleDayOfWeek : null,
          day_of_month: scheduleFrequency === 'monthly' ? scheduleDayOfMonth : null,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.detail || 'Scheduling failed');
      }

      const nextRun = data?.next_run_time ? ` Next run: ${data.next_run_time}` : '';
      setToastMsg(`Auto schedule created for ${target.trim()} (${scheduleFrequency}).${nextRun}`);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 5000);
    } catch (err: any) {
      setToastMsg(`Scheduling failed: ${err?.message || 'Unknown error'}`);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 5000);
    } finally {
      setIsScheduling(false);
    }
  };
  return (
    <main className="md:ml-64 pt-24 pb-12 px-8 min-h-screen scanner-scope">
      <div className="max-w-6xl mx-auto">
        {/* Page Header */}
        <div className="mb-10 flex flex-col md:flex-row md:items-end justify-between gap-6">
          <div>
            <div className="flex items-center gap-3">
              <h2 className="text-3xl font-extrabold tracking-tight text-on-surface leading-tight">Quantum Vulnerability Scanner</h2>
              <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography" target="_blank" rel="noopener noreferrer" className="w-6 h-6 rounded-full bg-surface-container-high border border-outline-variant/30 flex items-center justify-center hover:bg-primary/10 hover:text-primary transition-colors group relative cursor-pointer" title="NIST PQC Standards">
                <span className="material-symbols-outlined text-[14px]">info</span>
              </a>
            </div>
            <p className="text-on-surface-variant mt-2 max-w-xl">Initiate comprehensive cryptographic audits to identify legacy algorithms vulnerable to Shor's algorithm and ensure PQC compliance.</p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                if (!target.trim()) {
                  alert('Enter a domain first to export its website report.');
                  return;
                }
                window.open(`${apiBase}/api/reports/website/download?domain=${encodeURIComponent(target.trim())}&x_user_role=${encodeURIComponent(role)}`);
              }}
              className="px-5 py-2.5 bg-surface-container-highest text-on-surface rounded font-semibold text-sm transition-all hover:bg-surface-dim w-full sm:w-auto"
            >
              Website Report
            </button>
            <button
              onClick={() => {
                if (role !== 'Super Admin') {
                  alert('Only Super Admin can export the full CISO PDF report.');
                  return;
                }
                window.open(`${apiBase}/api/reports/download?x_user_role=${encodeURIComponent(role)}`);
              }}
              className="px-5 py-2.5 bg-surface-container-highest text-on-surface rounded font-semibold text-sm transition-all hover:bg-surface-dim w-full sm:w-auto"
            >
              Export Report
            </button>
            <button 
              onClick={handleScan}
              disabled={isScanning}
              className={`px-5 py-2.5 bg-gradient-to-br from-primary to-primary-container text-white rounded font-bold text-sm shadow-sm flex items-center gap-2 transition-all ${isScanning ? 'opacity-50 cursor-not-allowed' : 'active:scale-95'}`}
            >
              <span className="material-symbols-outlined text-sm flex items-center">{isScanning ? 'sync' : 'play_arrow'}</span>
              {isScanning ? 'Scanning...' : 'Start Scan'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-12 gap-8">
          {/* Input & Scanning Section */}
          <section className="col-span-12 lg:col-span-8 space-y-8">
            {/* Search/Input Area */}
            <div className="bg-surface-container-lowest rounded-xl p-6 shadow-sm">
              <label className="block text-[0.6875rem] font-bold uppercase tracking-wider text-on-surface-variant mb-4">Target Specification</label>
              <div className="flex flex-col sm:flex-row gap-4">
                <div className="relative flex-1">
                  <span className="absolute inset-y-0 left-4 flex items-center text-primary">
                    <span className="material-symbols-outlined flex items-center">language</span>
                  </span>
                  <input 
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    className="w-full bg-surface-container-low border-none rounded-lg py-4 pl-12 pr-4 text-on-surface font-medium focus:ring-2 focus:ring-primary/20 transition-all outline-none" 
                    placeholder="Enter Domain or IP Address" 
                    type="text" 
                  />
                </div>
                <select
                  value={scanMode}
                  onChange={(e) => setScanMode(e.target.value as 'Full Deep Scan' | 'Quick Scan')}
                  className="bg-surface-container-low rounded-lg py-4 px-4 text-sm font-bold text-on-surface-variant w-full sm:w-auto border border-outline-variant/20 outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value="Full Deep Scan">Full Deep Scan</option>
                  <option value="Quick Scan">Quick Scan</option>
                </select>
              </div>
            </div>

            {/* Results Panel */}
            <div className={`bg-surface-container-lowest rounded-xl p-8 shadow-sm ${!scanResult && !isScanning ? 'opacity-50 pointer-events-none' : ''}`}>
              <div className="flex items-center justify-between mb-8">
                <h3 className="text-sm font-bold uppercase tracking-wider text-on-surface-variant">Live Analysis Results</h3>
                <div className="flex items-center gap-2 text-[0.6875rem] font-bold py-1 px-3 bg-tertiary/10 text-tertiary rounded-full uppercase">
                  <span className={`w-1.5 h-1.5 bg-tertiary rounded-full ${isScanning ? 'animate-pulse' : ''}`}></span>
                  {isScanning ? 'Scanning...' : scanResult ? 'Analysis Complete' : 'Waiting for Input'}
                </div>
              </div>

              <div className="mb-6 flex items-start gap-2 rounded-lg border border-outline-variant/30 bg-surface-container-low px-3 py-2">
                <span className={`mt-1 h-2 w-2 rounded-full ${handshakeStatus.dotClass}`}></span>
                <div>
                  <p className="text-xs font-semibold text-on-surface">{handshakeStatus.label}</p>
                  <p className="text-[0.6875rem] text-on-surface-variant break-words">{handshakeStatus.detail}</p>
                </div>
              </div>

              {/* Scan Metrics Bento Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {/* TLS Version */}
                <div className="bg-surface-container-low rounded-lg p-5">
                  <p className="text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest mb-2">Protocol</p>
                  <div className="flex items-baseline justify-between">
                    <span className="text-xl font-bold text-on-surface">{scanResult?.scan_result?.tls_version || '---'}</span>
                    <span className="text-[0.625rem] font-bold py-0.5 px-2 bg-tertiary text-white rounded">SECURE</span>
                  </div>
                  <div className="mt-4 h-1 w-full bg-surface-variant rounded-full overflow-hidden">
                    <div className="h-full bg-tertiary w-full"></div>
                  </div>
                </div>

                {/* Key Exchange / Cipher Suite */}
                <div className="bg-surface-container-low rounded-lg p-5">
                  <p className="text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest mb-2">Key Exchange</p>
                  <div className="flex items-baseline justify-between">
                    <span className="text-xl font-bold text-on-surface">
                      {keyExchangeLabel}
                    </span>
                    <span className="text-[0.625rem] font-bold py-0.5 px-2 bg-tertiary text-white rounded">
                      {scanResult?.scan_result?.pqc_status || 'STANDARD'}
                    </span>
                  </div>
                  <p className="text-[0.65rem] text-on-surface-variant mt-3 font-medium truncate">{scanResult?.scan_result?.cipher_suite || 'Waiting for scan...'}</p>
                </div>

                {/* Key Length */}
                <div className="bg-surface-container-low rounded-lg p-5">
                  <p className="text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest mb-2">Key Strength</p>
                  <div className="flex items-baseline justify-between">
                    <span className="text-xl font-bold text-on-surface">{scanResult?.scan_result?.key_size ? `${scanResult.scan_result.key_size} Bits` : '---'}</span>
                    <span className="text-[0.625rem] font-bold py-0.5 px-2 bg-secondary text-white rounded">ROBUST</span>
                  </div>
                  <div className="mt-4 h-1 w-full bg-surface-variant rounded-full overflow-hidden">
                    <div className="h-full bg-secondary w-full"></div>
                  </div>
                </div>

                {/* Certificate Authority */}
                <div className="bg-surface-container-low rounded-lg p-5">
                  <p className="text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest mb-2">Certificate Authority</p>
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-primary flex items-center">verified_user</span>
                    <span className="text-sm font-bold text-on-surface truncate">{scanResult?.scan_result?.certificate_issuer || '---'}</span>
                  </div>
                  <p className="text-[0.65rem] text-on-surface-variant mt-2">Expires: {scanResult?.scan_result?.expiry_date || '---'}</p>
                </div>

                {/* Risk Level */}
                <div className="bg-surface-container-low rounded-lg p-5">
                  <p className="text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest mb-2">Quantum Risk Index</p>
                  <div className="flex items-baseline justify-between">
                    <span className={`text-xl font-bold ${scanResult?.risk?.risk_level === 'Critical' || scanResult?.risk?.risk_level === 'High' ? 'text-error' : scanResult?.risk?.risk_level === 'Medium' ? 'text-secondary' : 'text-tertiary'}`}>
                      {scanResult?.risk?.risk_level ? `${scanResult.risk.risk_level} Risk` : '---'}
                    </span>
                    <span className={`text-[0.625rem] font-bold py-0.5 px-2 ${scanResult?.risk?.risk_level === 'Critical' || scanResult?.risk?.risk_level === 'High' ? 'bg-error' : scanResult?.risk?.risk_level === 'Medium' ? 'bg-secondary' : 'bg-tertiary'} text-white rounded`}>
                      {scanResult?.risk?.score || 0}%
                    </span>
                  </div>
                  <div className="mt-4 text-xs font-medium text-on-surface-variant flex items-center justify-between">
                    <span>Algorithm: {scanResult?.scan_result?.algorithm || '---'}</span>
                    <span>Days left: {scanResult?.scan_result?.days_to_expiry !== undefined ? scanResult.scan_result.days_to_expiry : '---'}</span>
                  </div>
                </div>
                
                {/* Network Architecture */}
                <div className="bg-surface-container-low rounded-lg p-5">
                  <p className="text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest mb-2">Network Layer</p>
                  <div className="flex flex-col gap-2 mt-3">
                    <div className="flex items-center justify-between bg-surface-container-highest px-3 py-2 rounded">
                       <span className="text-[10px] uppercase font-bold text-on-surface-variant w-8">IPv4</span>
                       <span className="text-xs font-mono font-bold text-on-surface truncate ml-2">
                           {scanResult?.scan_result?.ipv4 || '---'}
                       </span>
                    </div>
                    <div className="flex items-center justify-between bg-surface-container-highest px-3 py-2 rounded">
                       <span className="text-[10px] uppercase font-bold text-on-surface-variant w-8">IPv6</span>
                       <span className="text-xs font-mono font-bold text-on-surface truncate ml-2">
                           {scanResult?.scan_result?.ipv6 || '---'}
                       </span>
                    </div>
                  </div>
                </div>
                
                {/* PQC Readiness */}
                <div className="bg-surface-container-low rounded-lg p-5">
                  <p className="text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest mb-2">PQC Readiness</p>
                  <div className="flex items-baseline justify-between">
                    <span className="text-xl font-bold text-tertiary">{scanResult?.risk?.label || '---'}</span>
                    <span className={`text-[0.625rem] font-bold py-0.5 px-2 ${scanResult?.risk?.status === 'Secure' ? 'bg-tertiary' : 'bg-error'} text-white rounded`}>{scanResult?.risk?.status?.toUpperCase() || '---'}</span>
                  </div>
                  <p className="text-[0.65rem] text-on-surface-variant mt-2 truncate">Analysis of algorithm {scanResult?.scan_result?.algorithm || ''}</p>
                </div>
                
                {/* 8. Crypto Migration Path */}
                <div className="bg-surface-container-low rounded-lg p-5">
                  <p className="text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest mb-2">Migration Path</p>
                  <div className="flex flex-col gap-2 mt-3">
                    <div className="flex items-center justify-between text-xs font-bold text-on-surface bg-surface-container-highest px-3 py-2 rounded">
                       <span>{scanResult?.scan_result?.algorithm || 'Current'}</span>
                       <span className="material-symbols-outlined text-[14px] text-on-surface-variant opacity-50">arrow_forward</span>
                       <span className="text-primary">{scanResult?.scan_result?.algorithm === 'RSA' ? 'Kyber-768' : 'NIST PQC Standard'}</span>
                    </div>
                    <div className="mt-1 text-[0.65rem] text-on-surface-variant font-medium">Recommended secure replacement logic.</div>
                  </div>
                </div>

                {/* 9. Scan Analytics */}
                <div className="bg-surface-container-low rounded-lg p-5">
                  <p className="text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest mb-2">Scan Performance</p>
                  <div className="flex items-baseline justify-between mt-1">
                    <span className="text-xl font-bold text-on-surface">{isScanning ? '--' : scanPerformance.duration}</span>
                    <span className="text-[0.625rem] font-bold py-0.5 px-2 bg-surface-container-highest text-on-surface rounded uppercase">{scanMode}</span>
                  </div>
                  <p className="text-[0.65rem] text-on-surface-variant mt-2 border-t border-surface-container-highest pt-2">Payloads Verified: {scanResult ? scanPerformance.payloads : 0}</p>
                </div>
                
                {/* Smart Risk Explanation (Full Width) */}
                {(scanResult?.risk?.reason || scanResult?.risk?.recommendation) && (
                  <div className="col-span-1 md:col-span-2 lg:col-span-3 bg-surface-container-low rounded-lg p-5 border-l-4 border-primary">
                    <p className="text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest mb-3 flex items-center gap-2">
                       <span className="material-symbols-outlined text-sm text-primary">psychology</span>
                       Smart Risk Explanation
                    </p>
                    <div className="space-y-3">
                       {scanResult.risk.reason && (
                           <div>
                              <span className="text-xs font-bold text-on-surface">Insight: </span>
                              <span className="text-xs text-on-surface-variant leading-relaxed">{scanResult.risk.reason}</span>
                           </div>
                       )}
                       {scanResult.risk.recommendation && (
                           <div>
                              <span className="text-xs font-bold text-on-surface">Action Required: </span>
                              <span className="text-xs text-on-surface-variant leading-relaxed font-medium">{scanResult.risk.recommendation}</span>
                           </div>
                       )}
                    </div>
                  </div>
                )}
              </div>

              {/* Subdomain Table with Filters */}
              {scanResult?.scan_result?.all_subdomains_detailed && (
                <div className="mt-8 bg-surface-container-low rounded-lg p-5 border border-outline-variant/20">
                  <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4 mb-5">
                    <div>
                      <p className="text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest">Subdomain Discovery</p>
                      <h4 className="text-sm font-bold text-on-surface mt-1">{scanResult?.name || target} - Subdomain Inventory</h4>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div className="px-3 py-2 rounded bg-surface-container-highest">Total: <span className="font-bold">{subdomainRows.length}</span></div>
                      <div className="px-3 py-2 rounded bg-surface-container-highest">Showing: <span className="font-bold">{Math.min((subdomainPage + 1) * subdomainPageSize, filteredSubdomainRows.length)}</span></div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-4">
                    <input
                      value={subdomainQuery}
                      onChange={(e) => setSubdomainQuery(e.target.value)}
                      className="md:col-span-2 bg-surface-container-highest border border-outline-variant/20 rounded px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-primary"
                      placeholder="Search subdomain..."
                      type="text"
                    />
                    <select
                      value={statusFilter}
                      onChange={(e) => setStatusFilter(e.target.value as 'all' | 'active' | 'inactive')}
                      className="bg-surface-container-highest border border-outline-variant/20 rounded px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-primary"
                    >
                      <option value="all">All Status</option>
                      <option value="active">Active</option>
                      <option value="inactive">Inactive</option>
                    </select>
                    <select
                      value={bucketFilter}
                      onChange={(e) => setBucketFilter(e.target.value as 'all' | 'pqc_ready' | 'standard' | 'critical')}
                      className="bg-surface-container-highest border border-outline-variant/20 rounded px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-primary"
                    >
                      <option value="all">All Criteria</option>
                      <option value="pqc_ready">PQC Ready</option>
                      <option value="standard">Standard</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>

                  <div className="overflow-x-auto rounded border border-outline-variant/20">
                    <table className="w-full text-left text-xs min-w-max">
                      <thead className="bg-surface-container-highest sticky top-0">
                        <tr>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Subdomain</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Status</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Criteria</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">SSL ⭐</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">TLS/SSL</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Algorithm</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Key Size</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Cipher Suite</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Issuer</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Expires</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Days Left</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Response</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Cert Valid</th>
                          <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Vulns</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pagedSubdomainRows.length === 0 ? (
                          <tr>
                            <td className="px-3 py-6 text-sm text-on-surface-variant" colSpan={14}>No subdomains match current filters.</td>
                          </tr>
                        ) : (
                          pagedSubdomainRows.map((row: any, idx: number) => (
                            <tr key={`${row.subdomain}-${idx}`} className="border-t border-outline-variant/10 hover:bg-surface-container-highest/50 transition-colors">
                              <td className="px-3 py-2 text-xs font-medium text-on-surface whitespace-nowrap">{row.subdomain || 'N/A'}</td>
                              <td className="px-3 py-2 text-xs whitespace-nowrap">
                                <span className={`px-2 py-1 rounded font-bold text-xs ${row.status === 'active' ? 'bg-tertiary/15 text-tertiary' : 'bg-error/15 text-error'}`}>
                                  {row.status || 'unknown'}
                                </span>
                              </td>
                              <td className="px-3 py-2 text-xs font-bold uppercase whitespace-nowrap">
                                <span className={`${row.bucket === 'pqc_ready' ? 'text-tertiary' : row.bucket === 'standard' ? 'text-secondary' : 'text-error'}`}>
                                  {String(row.bucket || 'critical').replace('_', ' ')}
                                </span>
                              </td>
                              <td className="px-3 py-2 text-xs font-bold whitespace-nowrap">{row.ssl_rating || 'N/A'}</td>
                              <td className="px-3 py-2 text-xs text-on-surface-variant whitespace-nowrap">{(row.tls_versions || []).join(', ') || 'N/A'}</td>
                              <td className="px-3 py-2 text-xs text-on-surface-variant font-medium whitespace-nowrap">{row.algorithm || 'N/A'}</td>
                              <td className="px-3 py-2 text-xs text-on-surface-variant font-mono whitespace-nowrap">{row.key_size ? `${row.key_size}b` : 'N/A'}</td>
                              <td className="px-3 py-2 text-xs text-on-surface-variant truncate max-w-xs" title={row.cipher_suite}>{row.cipher_suite ? row.cipher_suite.substring(0, 30) + '...' : 'N/A'}</td>
                              <td className="px-3 py-2 text-xs text-on-surface-variant truncate max-w-sm" title={row.certificate_issuer}>{row.certificate_issuer ? row.certificate_issuer.substring(0, 25) : 'N/A'}</td>
                              <td className="px-3 py-2 text-xs text-on-surface-variant whitespace-nowrap">{row.expiry_date ? new Date(row.expiry_date).toLocaleDateString() : 'N/A'}</td>
                              <td className="px-3 py-2 text-xs font-bold whitespace-nowrap">
                                <span className={`${row.days_to_expiry === null ? 'text-on-surface-variant' : row.days_to_expiry < 30 ? 'text-error' : row.days_to_expiry < 90 ? 'text-secondary' : 'text-tertiary'}`}>
                                  {row.days_to_expiry ?? 'N/A'}
                                </span>
                              </td>
                              <td className="px-3 py-2 text-xs text-on-surface-variant whitespace-nowrap">{row.response_time_ms ? `${row.response_time_ms}ms` : 'N/A'}</td>
                              <td className="px-3 py-2 text-xs whitespace-nowrap">
                                <span className={`px-2 py-1 rounded font-bold text-xs ${row.certificate_valid ? 'bg-tertiary/15 text-tertiary' : 'bg-error/15 text-error'}`}>
                                  {row.certificate_valid ? '✓' : '✗'}
                                </span>
                              </td>
                              <td className="px-3 py-2 text-xs whitespace-nowrap">
                                <span className={`px-2 py-1 rounded font-bold text-xs ${row.has_vulnerabilities ? 'bg-error/15 text-error' : 'bg-tertiary/15 text-tertiary'}`}>
                                  {row.has_vulnerabilities ? '⚠️' : 'None'}
                                </span>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>

                  {filteredSubdomainRows.length > subdomainPageSize && (
                    <div className="mt-4 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
                      <p className="text-on-surface-variant">
                        Page <span className="font-bold text-on-surface">{subdomainPage + 1}</span> of <span className="font-bold text-on-surface">{subdomainPageCount}</span>
                      </p>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => setSubdomainPage((page) => Math.max(0, page - 1))}
                          disabled={subdomainPage === 0}
                          className="px-3 py-2 rounded bg-surface-container-highest text-on-surface font-semibold disabled:opacity-40 disabled:cursor-not-allowed hover:bg-surface-variant transition-colors"
                        >
                          Previous 10
                        </button>
                        <button
                          type="button"
                          onClick={() => setSubdomainPage((page) => Math.min(subdomainPageCount - 1, page + 1))}
                          disabled={subdomainPage >= subdomainPageCount - 1}
                          className="px-3 py-2 rounded bg-primary text-white font-semibold disabled:opacity-40 disabled:cursor-not-allowed hover:opacity-90 transition-colors"
                        >
                          Next 10
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {scanResult && (
                <div className="mt-8 bg-surface-container-low rounded-lg p-5 border border-outline-variant/20">
                  <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4 mb-5">
                    <div>
                      <p className="text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest">Mobile App Similarity Report</p>
                      <h4 className="text-sm font-bold text-on-surface mt-1">Apps matching {scanResult?.name || target}</h4>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div className="px-3 py-2 rounded bg-surface-container-highest">Total: <span className="font-bold">{scanResult?.scan_result?.mobile_info?.mobile_apps_found || 0}</span></div>
                      <div className="px-3 py-2 rounded bg-surface-container-highest">Top Match: <span className="font-bold">{topMobileMatch?.name || 'N/A'}</span></div>
                    </div>
                  </div>

                  {mobileApps.length === 0 ? (
                    <p className="text-sm text-on-surface-variant">No matching mobile apps found for this domain.</p>
                  ) : (
                    <div className="overflow-x-auto rounded border border-outline-variant/20">
                      <table className="w-full text-left text-xs min-w-max">
                        <thead className="bg-surface-container-highest">
                          <tr>
                            <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Platform</th>
                            <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">App Name</th>
                            <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Relevance</th>
                            <th className="px-3 py-2 text-[10px] uppercase tracking-wider text-on-surface-variant font-bold whitespace-nowrap">Store Link</th>
                          </tr>
                        </thead>
                        <tbody>
                          {mobileApps.slice(0, 20).map((app: any, idx: number) => (
                            <tr key={`${app.platform}-${app.app_id || idx}`} className="border-t border-outline-variant/10 hover:bg-surface-container-highest/50 transition-colors">
                              <td className="px-3 py-2 text-xs font-medium capitalize">{app.platform || 'unknown'}</td>
                              <td className="px-3 py-2 text-xs font-medium">{app.name || 'Unknown'}</td>
                              <td className="px-3 py-2 text-xs font-bold">{typeof app.relevance === 'number' ? `${Math.round(app.relevance * 100)}%` : 'N/A'}</td>
                              <td className="px-3 py-2 text-xs">
                                {app.store_url ? (
                                  <a href={app.store_url} target="_blank" rel="noreferrer" className="text-primary underline">Open</a>
                                ) : 'N/A'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          </section>

          {/* Sidebar Content: Scheduling & History */}
          <aside className="col-span-12 lg:col-span-4 space-y-8">
            {/* Auto Scheduling Section */}
            <div className="bg-surface-container-lowest rounded-xl p-6 shadow-sm border border-transparent">
              <div className="flex items-center gap-3 mb-6">
                <span className="material-symbols-outlined text-primary flex items-center">calendar_month</span>
                <h3 className="text-sm font-bold uppercase tracking-wider text-on-surface">Auto Scheduling</h3>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="block text-[0.65rem] font-bold uppercase tracking-wider text-on-surface-variant mb-1">Frequency</label>
                  <select
                    value={scheduleFrequency}
                    onChange={(e) => setScheduleFrequency(e.target.value as 'daily' | 'weekly' | 'monthly')}
                    className="w-full bg-surface-container-low border border-outline-variant/20 rounded px-3 py-2 text-xs font-semibold outline-none focus:ring-1 focus:ring-primary"
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>

                {scheduleFrequency === 'weekly' && (
                  <div>
                    <label className="block text-[0.65rem] font-bold uppercase tracking-wider text-on-surface-variant mb-1">Day of Week</label>
                    <select
                      value={scheduleDayOfWeek}
                      onChange={(e) => setScheduleDayOfWeek(e.target.value)}
                      className="w-full bg-surface-container-low border border-outline-variant/20 rounded px-3 py-2 text-xs font-semibold outline-none focus:ring-1 focus:ring-primary"
                    >
                      <option value="mon">Monday</option>
                      <option value="tue">Tuesday</option>
                      <option value="wed">Wednesday</option>
                      <option value="thu">Thursday</option>
                      <option value="fri">Friday</option>
                      <option value="sat">Saturday</option>
                      <option value="sun">Sunday</option>
                    </select>
                  </div>
                )}

                {scheduleFrequency === 'monthly' && (
                  <div>
                    <label className="block text-[0.65rem] font-bold uppercase tracking-wider text-on-surface-variant mb-1">Day of Month</label>
                    <input
                      type="number"
                      min={1}
                      max={28}
                      value={scheduleDayOfMonth}
                      onChange={(e) => setScheduleDayOfMonth(Math.max(1, Math.min(28, Number(e.target.value) || 1)))}
                      className="w-full bg-surface-container-low border border-outline-variant/20 rounded px-3 py-2 text-xs font-semibold outline-none focus:ring-1 focus:ring-primary"
                    />
                  </div>
                )}

                <div>
                  <label className="block text-[0.65rem] font-bold uppercase tracking-wider text-on-surface-variant mb-1">Time</label>
                  <input
                    type="time"
                    value={scheduleTime}
                    onChange={(e) => setScheduleTime(e.target.value)}
                    className="w-full bg-surface-container-low border border-outline-variant/20 rounded px-3 py-2 text-xs font-semibold outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>

                <div>
                  <label className="block text-[0.65rem] font-bold uppercase tracking-wider text-on-surface-variant mb-1">Email</label>
                  <input
                    type="email"
                    value={scheduleEmail}
                    onChange={(e) => setScheduleEmail(e.target.value)}
                    placeholder="abc@gmail.com"
                    className="w-full bg-surface-container-low border border-outline-variant/20 rounded px-3 py-2 text-xs font-semibold outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>

              <button onClick={handleSchedule} disabled={isScheduling} className={`w-full mt-6 py-2.5 bg-gradient-to-br from-primary to-primary-container text-white rounded font-bold text-xs transition-all hover:shadow-lg active:scale-95 flex items-center justify-center gap-2 ${isScheduling ? 'opacity-60 cursor-not-allowed' : ''}`}>
                <span className="material-symbols-outlined text-[14px]">auto_mode</span>
                {isScheduling ? 'Scheduling...' : 'Auto Schedule Scan'}
              </button>
            </div>

            {/* Risk Formula Transparency */}
            <div className="bg-surface-container-lowest rounded-xl p-6 shadow-sm border border-outline-variant/20">
              <h3 className="text-sm font-bold uppercase tracking-wider text-on-surface mb-4">Risk Formula Transparency</h3>
              <div className="space-y-4 text-xs text-on-surface-variant">
                <div className="bg-surface-container-low rounded p-3 border border-outline-variant/20">
                  <p className="font-bold text-on-surface mb-2">Core Score Formula</p>
                  <div className="font-mono text-[11px] leading-6 bg-surface-container-highest rounded p-3 border border-outline-variant/20">
                    <p>Total Penalty = (w1 x Crypto) + (w2 x Protocol) + (w3 x Vulnerability) + (w4 x Exposure) + (w5 x Third-Party) + (w6 x Governance)</p>
                    <p className="mt-2">Score (raw) = max(0, 100 - Total Penalty)</p>
                    <p className="mt-2">Final Score applies post-rules: PQC floor and expired certificate cap.</p>
                    <p className="mt-2 text-[10px]">Formula Version: {scanResult?.risk?.formula_version || 'v2-6factor-weighted-penalty'}</p>
                  </div>
                </div>

                <div className="bg-surface-container-low rounded p-3 border border-outline-variant/20">
                  <p className="font-bold text-on-surface mb-2">Live Factor Contributions</p>
                  <div className="font-mono text-[10px] leading-5 bg-surface-container-highest rounded p-3 border border-outline-variant/20 overflow-x-auto">
                    <table className="w-full min-w-[420px] text-left">
                      <thead>
                        <tr className="text-on-surface-variant">
                          <th className="pr-3">Factor</th>
                          <th className="pr-3">Value</th>
                          <th className="pr-3">Weight</th>
                          <th>Weighted</th>
                        </tr>
                      </thead>
                      <tbody>
                        {riskContributionRows.map((row) => (
                          <tr key={row.key} className="text-on-surface">
                            <td className="pr-3 py-1">{row.label}</td>
                            <td className="pr-3 py-1">{row.factorValue}</td>
                            <td className="pr-3 py-1">{row.weight.toFixed(2)}</td>
                            <td className="py-1">{row.contribution.toFixed(2)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    <p className="mt-3">Total Penalty = {scanResult?.risk?.total_penalty ?? computedPenalty}</p>
                    <p>Score (raw) = {scanResult?.risk?.score_pre_overrides ?? Math.max(0, Math.floor(100 - (scanResult?.risk?.total_penalty ?? computedPenalty)))}</p>
                    <p>Score (final) = {scanResult?.risk?.score ?? 0}</p>
                  </div>
                </div>

                <div className="bg-surface-container-low rounded p-3 border border-outline-variant/20">
                  <p className="font-bold text-on-surface mb-2">Crypto Risk Rules</p>
                  <p>RSA adds +60. ECC/ECDSA adds +30.</p>
                  <p>RSA key penalties: &lt;2048 adds +40, 2048 adds +20.</p>
                  <p>ECC key penalties: &lt;224 adds +40, &lt;256 adds +20.</p>
                </div>

                <div className="bg-surface-container-low rounded p-3 border border-outline-variant/20">
                  <p className="font-bold text-on-surface mb-2">Protocol Risk Rules</p>
                  <p>If TLS 1.1/1.0 present -&gt; Protocol Risk = 100.</p>
                  <p>If TLS 1.2 + 1.3 together -&gt; Protocol Risk = 60 (dual compatibility penalty).</p>
                  <p>If only TLS 1.2 -&gt; Protocol Risk = 50. If only TLS 1.3 -&gt; Protocol Risk = 0.</p>
                </div>

                <div className="bg-surface-container-low rounded p-3 border border-outline-variant/20">
                  <p className="font-bold text-on-surface mb-2">Risk Bands</p>
                  <p>Score &gt;= 80: Low (PQC Ready)</p>
                  <p>60-79: Medium (Quantum Safe)</p>
                  <p>40-59: High (Needs Upgrade)</p>
                  <p>&lt;40: Critical (Not Safe)</p>
                </div>

                <div className="bg-surface-container-low rounded p-3 border border-outline-variant/20">
                  <p className="font-bold text-on-surface mb-2">Post-Formula Adjustments</p>
                  {Array.isArray(scanResult?.risk?.adjustments) && scanResult.risk.adjustments.length > 0 ? (
                    <div className="space-y-1">
                      {scanResult.risk.adjustments.map((item: string, idx: number) => (
                        <p key={`${item}-${idx}`}>- {item}</p>
                      ))}
                    </div>
                  ) : (
                    <p>No post-formula adjustments were applied for this scan.</p>
                  )}
                </div>

                <div className="bg-surface-container-low rounded p-3 border border-outline-variant/20">
                  <p className="font-bold text-on-surface mb-2">Classification Math</p>
                  <div className="font-mono text-[10px] leading-5 bg-surface-container-highest rounded p-3 border border-outline-variant/20 overflow-x-auto">
                    <div className="flex items-start gap-1 min-w-[300px]">
                      <span>Improvement%</span>
                      <span>=</span>
                      <div className="inline-flex flex-col items-center min-w-[190px]">
                        <span className="border-b border-on-surface px-2 text-center">(BS - CS) x 100</span>
                        <span className="px-2 text-center">BS</span>
                      </div>
                    </div>
                  </div>
                  <p className="mt-2 text-[10px] text-on-surface-variant">BS = Baseline Score</p>
                  <p className="text-[10px] text-on-surface-variant">CS = Current Score</p>
                </div>
              </div>
            </div>
          </aside>
        </div>
      </div>
      {/* Toast Notification */}
      {showToast && (
        <div className="fixed bottom-8 right-8 bg-surface-container-highest text-on-surface px-6 py-4 rounded-xl shadow-2xl flex items-center gap-4 z-50 animate-in fade-in slide-in-from-bottom-8">
          <span className="material-symbols-outlined text-primary">check_circle</span>
          <p className="text-sm font-bold">{toastMsg}</p>
        </div>
      )}
    </main>
  );
};

export default Scanner;

