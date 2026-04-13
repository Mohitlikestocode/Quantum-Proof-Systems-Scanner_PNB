import { useEffect, useMemo, useState } from 'react';

type ReportsOverview = {
  generated_at?: string;
  asset_discovery?: { summary?: { total_domains?: number; active_domains?: number; inactive_domains?: number } };
  subdomain_risk?: { summary?: { total_subdomains?: number; pqc_ready?: number; standard?: number; critical?: number } };
  vulnerability?: { summary?: { vulnerable_domains?: number; high_severity_domains?: number; third_party_hosted?: number } };
  mobile_app?: { summary?: { domains_with_mobile_apps?: number; total_apps?: number; android_apps?: number; ios_apps?: number } };
};

type ReportHistoryRow = {
  report_id: string;
  timestamp: string;
  domain: string;
  risk_level: string;
  score: number;
  generated_by: string;
};

const Reports = () => {
  const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8010';
  const [overview, setOverview] = useState<ReportsOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [historyRows, setHistoryRows] = useState<ReportHistoryRow[]>([]);
  const [historyFilter, setHistoryFilter] = useState('');
  const [historyLoading, setHistoryLoading] = useState(true);
  const [reportDomain, setReportDomain] = useState('');
  const [reportRecipient, setReportRecipient] = useState(localStorage.getItem('userEmail') || '');
  const [includeHistory, setIncludeHistory] = useState(true);
  const [sendingReport, setSendingReport] = useState(false);
  const role = localStorage.getItem('userRole') || 'User';
  const canExportPdf = role !== 'User';
  const canExportCiso = role === 'Super Admin';

  const openJsonReport = (endpoint: string) => {
    window.open(`${apiBase}${endpoint}`, '_blank');
  };

  const openPdfReport = (endpoint: string) => {
    if (!canExportPdf) {
      alert('Your role can view reports but cannot export PDFs.');
      return;
    }
    window.open(`${apiBase}${endpoint}?x_user_role=${encodeURIComponent(role)}`, '_blank');
  };

  useEffect(() => {
    const loadOverview = async () => {
      try {
        const response = await fetch(`${apiBase}/api/reports/overview`);
        if (!response.ok) {
          throw new Error('Failed to load reports overview');
        }
        const data: ReportsOverview = await response.json();
        setOverview(data);
      } catch (error) {
        console.error('Unable to load reports overview', error);
      } finally {
        setLoading(false);
      }
    };

    loadOverview();
  }, [apiBase]);

  useEffect(() => {
    const loadHistory = async () => {
      setHistoryLoading(true);
      try {
        const query = historyFilter.trim() ? `?domain=${encodeURIComponent(historyFilter.trim())}` : '';
        const response = await fetch(`${apiBase}/api/reports/history${query}`);
        if (!response.ok) {
          throw new Error('Failed to load report history');
        }
        const data = await response.json();
        setHistoryRows(data?.data || []);
      } catch (error) {
        console.error('Unable to load report history', error);
        setHistoryRows([]);
      } finally {
        setHistoryLoading(false);
      }
    };

    loadHistory();
  }, [apiBase, historyFilter]);

  const handleSendDomainReport = async () => {
    if (!reportDomain.trim() || !reportRecipient.trim()) {
      alert('Enter both company domain and recipient email.');
      return;
    }

    setSendingReport(true);
    try {
      const response = await fetch(`${apiBase}/api/reports/company/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: reportDomain.trim(),
          recipient: reportRecipient.trim(),
          include_history: includeHistory,
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data?.detail || 'Failed to send company report email');
      }

      alert(data?.message || 'Report sent successfully.');
      setHistoryFilter(reportDomain.trim());
    } catch (error: any) {
      alert(error?.message || 'Failed to send report.');
    } finally {
      setSendingReport(false);
    }
  };

  const summary = useMemo(() => {
    const totalDomains = overview?.asset_discovery?.summary?.total_domains ?? 0;
    const activeDomains = overview?.asset_discovery?.summary?.active_domains ?? 0;
    const totalSubdomains = overview?.subdomain_risk?.summary?.total_subdomains ?? 0;
    const criticalSubdomains = overview?.subdomain_risk?.summary?.critical ?? 0;
    const vulnerableDomains = overview?.vulnerability?.summary?.vulnerable_domains ?? 0;
    const mobileApps = overview?.mobile_app?.summary?.total_apps ?? 0;

    return {
      totalDomains,
      activeDomains,
      totalSubdomains,
      criticalSubdomains,
      vulnerableDomains,
      mobileApps,
      activePct: totalDomains > 0 ? Math.round((activeDomains / totalDomains) * 100) : 0
    };
  }, [overview]);

  return (
    <main className="md:ml-64 pt-16 min-h-screen">
      <div className="max-w-[1200px] mx-auto p-12">
        {/* Page Header */}
        <header className="mb-12 flex flex-col md:flex-row md:items-end justify-between gap-6">
          <div>
            <h2 className="text-[1.75rem] font-bold tracking-tight text-on-surface mb-2">Reports & Audit Logs</h2>
            <p className="text-on-surface-variant max-w-xl">Comprehensive analytical oversight of your organization's transition to post-quantum cryptographic standards.</p>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => setHistoryFilter(reportDomain.trim() || historyFilter)} className="flex items-center gap-2 px-4 py-2.5 bg-surface-container-lowest text-on-surface border border-outline-variant/20 rounded-lg hover:bg-surface-container-low transition-colors shadow-sm font-medium text-sm w-full sm:w-auto">
              <span className="material-symbols-outlined text-lg" data-icon="calendar_month">calendar_month</span>
              Refresh History
            </button>
            <button
              onClick={() => {
                if (!canExportCiso) {
                  alert('Only Super Admin can export the full CISO PDF report.');
                  return;
                }
                window.open(`${apiBase}/api/reports/download?x_user_role=${encodeURIComponent(role)}`, '_blank');
              }}
              className="flex items-center gap-2 px-6 py-2.5 bg-gradient-to-br from-primary to-primary-container text-white rounded-lg font-bold shadow-md hover:shadow-lg active:scale-95 transition-all text-sm w-full sm:w-auto"
            >
              <span className="material-symbols-outlined text-lg" data-icon="download">download</span>
              Export Report
            </button>
          </div>
        </header>

        {/* Bento Grid Layout */}
        <div className="grid grid-cols-12 gap-8">
          {/* Smart Reporting: AI Summary (NEW) */}
          <section className="col-span-12 lg:col-span-8">
            <div className="bg-surface-container-lowest p-8 rounded-xl shadow-[0_4px_24px_rgba(0,0,0,0.04)] border border-outline-variant/10">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                    <span className="material-symbols-outlined" data-icon="smart_toy">smart_toy</span>
                  </div>
                  <h3 className="text-lg font-bold text-on-surface">Smart AI Synthesis</h3>
                </div>
                <span className="px-2.5 py-1 bg-tertiary/10 text-tertiary text-[0.6875rem] font-bold uppercase tracking-wider rounded">Report Generated Today</span>
              </div>
              <div className="space-y-6">
                <div className="p-6 bg-surface-container-low rounded-xl border-l-4 border-primary">
                  <h4 className="text-sm font-bold text-primary mb-2 uppercase tracking-tight">Executive Summary</h4>
                  <p className="text-[0.875rem] leading-relaxed text-on-surface-variant">
                    {loading ? 'Generating unified reports...' : (
                      <>
                        Scanned <span className="text-primary font-semibold">{summary.totalDomains} domains</span> with <span className="text-primary font-semibold">{summary.activePct}% active availability</span>. 
                        Current report set includes <span className="text-primary font-semibold">{summary.totalSubdomains} subdomains</span>, 
                        <span className="text-error font-semibold"> {summary.criticalSubdomains} critical subdomains</span>, 
                        <span className="text-error font-semibold"> {summary.vulnerableDomains} vulnerable domains</span>, and 
                        <span className="text-secondary font-semibold"> {summary.mobileApps} mobile apps</span> discovered.
                      </>
                    )}
                  </p>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="p-5 bg-surface-container-lowest border border-outline-variant/10 rounded-lg flex flex-col items-start">
                    <div className="flex items-center gap-2 mb-3">
                      <span className="material-symbols-outlined text-tertiary text-lg" data-icon="check_circle">check_circle</span>
                      <span className="text-xs font-bold uppercase tracking-wider text-on-surface-variant">Risk Mitigation</span>
                    </div>
                    <p className="text-sm text-on-surface font-medium leading-snug">
                      {loading
                        ? 'Compiling active/inactive domain report...'
                        : `${summary.activeDomains} active domains are currently reachable and included in governance reporting.`}
                    </p>
                  </div>
                  <div className="p-5 bg-surface-container-lowest border border-outline-variant/10 rounded-lg flex flex-col items-start">
                    <div className="flex items-center gap-2 mb-3">
                      <span className="material-symbols-outlined text-secondary text-lg" data-icon="info">info</span>
                      <span className="text-xs font-bold uppercase tracking-wider text-on-surface-variant">Attention Required</span>
                    </div>
                    <p className="text-sm text-on-surface font-medium leading-snug">
                      {loading
                        ? 'Compiling vulnerability and third-party exposure report...'
                        : `${summary.vulnerableDomains} domains are currently flagged in the vulnerability report and need remediation tracking.`}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Export & Schedule Section */}
          <section className="col-span-12 lg:col-span-4 flex flex-col gap-8">
            {/* Export Options */}
            <div className="bg-surface-container-lowest p-6 rounded-xl shadow-[0_4px_24px_rgba(0,0,0,0.04)] border border-outline-variant/10">
              <h3 className="text-sm font-bold text-on-surface mb-6 uppercase tracking-wider">Modular Audit Reports</h3>
              <div className="grid grid-cols-2 gap-2 mb-4 text-xs">
                <div className="rounded-md bg-surface-container-low px-3 py-2 text-on-surface-variant">Domains: <span className="font-bold text-on-surface">{summary.totalDomains}</span></div>
                <div className="rounded-md bg-surface-container-low px-3 py-2 text-on-surface-variant">Subdomains: <span className="font-bold text-on-surface">{summary.totalSubdomains}</span></div>
                <div className="rounded-md bg-surface-container-low px-3 py-2 text-on-surface-variant">Critical: <span className="font-bold text-error">{summary.criticalSubdomains}</span></div>
                <div className="rounded-md bg-surface-container-low px-3 py-2 text-on-surface-variant">Mobile Apps: <span className="font-bold text-on-surface">{summary.mobileApps}</span></div>
              </div>
              <div className="space-y-3">
                <div className="p-3 rounded-lg border border-outline-variant/20 bg-surface-container-lowest">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <span className="material-symbols-outlined text-primary" data-icon="search_check">search_check</span>
                      <span className="text-sm font-medium">1. Asset Discovery</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={() => openJsonReport('/api/reports/asset-discovery')} className="px-3 py-1.5 text-xs font-bold rounded-md border border-outline-variant/30 hover:bg-surface-container-low transition-colors">JSON</button>
                      <button onClick={() => openPdfReport('/api/reports/asset-discovery/download')} className="px-3 py-1.5 text-xs font-bold rounded-md bg-primary text-white hover:bg-primary/90 transition-colors">PDF</button>
                    </div>
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-outline-variant/20 bg-surface-container-lowest">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <span className="material-symbols-outlined text-tertiary" data-icon="lan">lan</span>
                      <span className="text-sm font-medium">2. Subdomain Risk</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={() => openJsonReport('/api/reports/subdomain-risk')} className="px-3 py-1.5 text-xs font-bold rounded-md border border-outline-variant/30 hover:bg-surface-container-low transition-colors">JSON</button>
                      <button onClick={() => openPdfReport('/api/reports/subdomain-risk/download')} className="px-3 py-1.5 text-xs font-bold rounded-md bg-primary text-white hover:bg-primary/90 transition-colors">PDF</button>
                    </div>
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-error/30 bg-error/5">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <span className="material-symbols-outlined text-error" data-icon="manage_search">manage_search</span>
                      <span className="text-sm font-medium text-error font-bold">3. Vulnerability Report</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={() => openJsonReport('/api/reports/vulnerability')} className="px-3 py-1.5 text-xs font-bold rounded-md border border-error/30 text-error hover:bg-error/10 transition-colors">JSON</button>
                      <button onClick={() => openPdfReport('/api/reports/vulnerability/download')} className="px-3 py-1.5 text-xs font-bold rounded-md bg-error text-white hover:bg-error/90 transition-colors">PDF</button>
                    </div>
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-outline-variant/20 bg-surface-container-lowest">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <span className="material-symbols-outlined text-secondary" data-icon="smartphone">smartphone</span>
                      <span className="text-sm font-medium">4. Mobile App Report</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={() => openJsonReport('/api/reports/mobile-app')} className="px-3 py-1.5 text-xs font-bold rounded-md border border-outline-variant/30 hover:bg-surface-container-low transition-colors">JSON</button>
                      <button onClick={() => openPdfReport('/api/reports/mobile-app/download')} className="px-3 py-1.5 text-xs font-bold rounded-md bg-primary text-white hover:bg-primary/90 transition-colors">PDF</button>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Company Report Email */}
            <div className="bg-surface-container-lowest p-6 rounded-xl shadow-[0_4px_24px_rgba(0,0,0,0.04)] border border-outline-variant/10">
              <h3 className="text-sm font-bold text-on-surface mb-6 uppercase tracking-wider">Company Report Email</h3>
              <div className="space-y-3">
                <input
                  value={reportDomain}
                  onChange={(e) => setReportDomain(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded-md bg-surface-container-low border border-outline-variant/25"
                  placeholder="Company domain, e.g. google.com"
                />
                <input
                  type="email"
                  value={reportRecipient}
                  onChange={(e) => setReportRecipient(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded-md bg-surface-container-low border border-outline-variant/25"
                  placeholder="Recipient email"
                />
                <label className="flex items-center gap-2 text-xs text-on-surface-variant">
                  <input type="checkbox" checked={includeHistory} onChange={(e) => setIncludeHistory(e.target.checked)} />
                  Include historical scans for this company
                </label>
                <button
                  onClick={handleSendDomainReport}
                  disabled={sendingReport}
                  className={`w-full py-2 text-xs font-bold rounded-md text-white bg-gradient-to-br from-primary to-primary-container ${sendingReport ? 'opacity-60 cursor-not-allowed' : ''}`}
                >
                  {sendingReport ? 'Sending...' : 'Send Domain Report'}
                </button>
              </div>
            </div>
          </section>

          {/* Historical Audit Log */}
          <section className="col-span-12">
            <div className="bg-surface-container-lowest rounded-xl shadow-[0_4px_24px_rgba(0,0,0,0.04)] border border-outline-variant/10 overflow-hidden">
              <div className="px-8 py-6 border-b border-surface-container-low flex items-center justify-between">
                <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider">Historical Audit Logs</h3>
                <div className="flex items-center gap-2">
                  <input value={historyFilter} onChange={(e) => setHistoryFilter(e.target.value)} className="px-4 py-1.5 text-xs bg-surface-container-low border-none rounded-lg focus:ring-1 focus:ring-primary w-64 outline-none w-full sm:w-64" placeholder="Filter by domain..." type="text" />
                  <button className="p-1.5 hover:bg-surface-container-low rounded transition-colors">
                    <span className="material-symbols-outlined text-on-surface-variant" data-icon="filter_list">filter_list</span>
                  </button>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="bg-surface-container-low/50">
                      <th className="px-8 py-3 text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest">Report ID</th>
                      <th className="px-8 py-3 text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest">Timestamp</th>
                      <th className="px-8 py-3 text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest">Status Score</th>
                      <th className="px-8 py-3 text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest">Generated By</th>
                      <th className="px-8 py-3 text-[0.6875rem] font-bold text-on-surface-variant uppercase tracking-widest text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-surface-container-low">
                    {historyLoading ? (
                      <tr><td className="px-8 py-4 text-sm text-on-surface-variant" colSpan={5}>Loading history...</td></tr>
                    ) : historyRows.length === 0 ? (
                      <tr><td className="px-8 py-4 text-sm text-on-surface-variant" colSpan={5}>No history found.</td></tr>
                    ) : historyRows.map((row) => {
                      const safeScore = Math.max(0, Math.min(100, Number(row.score || 0)));
                      const riskLower = String(row.risk_level || '').toLowerCase();
                      const color = riskLower.includes('high') || riskLower.includes('critical') ? 'bg-error text-error' : riskLower.includes('medium') ? 'bg-secondary text-secondary' : 'bg-tertiary text-tertiary';
                      return (
                        <tr key={`${row.report_id}-${row.timestamp}`} className="hover:bg-surface-container-low transition-colors group">
                          <td className="px-8 py-4 text-xs font-mono font-bold text-primary">{row.report_id}</td>
                          <td className="px-8 py-4 text-sm text-on-surface-variant">{row.timestamp ? new Date(row.timestamp).toLocaleString() : 'N/A'}</td>
                          <td className="px-8 py-4">
                            <div className="flex items-center gap-2">
                              <div className="w-16 h-1.5 bg-surface-container-high rounded-full overflow-hidden">
                                <div className={`h-full ${color.split(' ')[0]}`} style={{ width: `${safeScore}%` }}></div>
                              </div>
                              <span className={`text-xs font-bold ${color.split(' ')[1]}`}>{safeScore}%</span>
                            </div>
                          </td>
                          <td className="px-8 py-4 text-sm font-medium">{row.generated_by || 'System'} - {row.domain}</td>
                          <td className="px-8 py-4 text-right">
                            <button onClick={() => openJsonReport(`/api/reports/website?domain=${encodeURIComponent(row.domain)}`)} className="text-on-surface-variant hover:text-primary transition-colors w-full sm:w-auto">
                              <span className="material-symbols-outlined" data-icon="visibility">visibility</span>
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <div className="px-8 py-4 bg-surface-container-low/30 flex items-center justify-between">
                <span className="text-xs text-on-surface-variant font-medium">Showing {historyRows.length} report rows</span>
                <div className="flex items-center gap-1">
                  <button onClick={() => setHistoryFilter('')} className="px-3 py-1 text-xs font-bold text-on-surface bg-surface-container-lowest border border-outline-variant/20 rounded w-full sm:w-auto">Clear Filter</button>
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
};

export default Reports;
