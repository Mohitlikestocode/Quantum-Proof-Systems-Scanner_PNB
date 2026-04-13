import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import ForceGraph2D from 'react-force-graph-2d';

type DiscoveryTab = 'Domains' | 'SSL Certificates' | 'IP Addresses/Subnets' | 'Software';

const AssetDiscovery = () => {
  const navigate = useNavigate();
  const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8010';

  const [assets, setAssets] = useState<any[]>([]);
  const [graphData, setGraphData] = useState<{ nodes: any[]; links: any[] }>({ nodes: [], links: [] });
  const [activeTab, setActiveTab] = useState<DiscoveryTab>('Domains');
  const [highRiskOnly, setHighRiskOnly] = useState(false);
  const [sortBy, setSortBy] = useState<'Risk Level' | 'Discovery Date' | 'Alpha'>('Risk Level');
  const [page, setPage] = useState(0);

  useEffect(() => {
    fetch(apiBase + '/api/assets')
      .then((res) => res.json())
      .then((data) => setAssets(Array.isArray(data) ? data : []))
      .catch((err) => console.error('Failed to fetch assets', err));

    fetch(apiBase + '/api/graph')
      .then((res) => res.json())
      .then((data) => {
        setGraphData({
          nodes: data?.nodes || [],
          links: (data?.edges || []).map((e: any) => ({ source: e.source, target: e.target })),
        });
      })
      .catch((err) => console.error('Failed to fetch graph data', err));
  }, [apiBase]);

  const discoveredRows = useMemo(() => {
    const rows = assets.filter((asset) => {
      const name = String(asset?.name || '').toLowerCase();
      const type = String(asset?.type || '').toLowerCase();
      const hasCert = !!asset?.scan_result?.certificate_issuer;
      const hasIp = !!asset?.ip_address || !!asset?.scan_result?.ipv4;

      if (activeTab === 'Domains') return name.includes('.') || type.includes('domain');
      if (activeTab === 'SSL Certificates') return hasCert;
      if (activeTab === 'IP Addresses/Subnets') return hasIp;
      return type.includes('software') || type.includes('api') || type.includes('service');
    });

    const filtered = highRiskOnly
      ? rows.filter((asset) => ['high', 'critical'].includes(String(asset?.risk?.risk_level || '').toLowerCase()))
      : rows;

    const sorted = [...filtered];
    if (sortBy === 'Alpha') {
      sorted.sort((a, b) => String(a?.name || '').localeCompare(String(b?.name || '')));
    } else if (sortBy === 'Discovery Date') {
      sorted.sort((a, b) => String(b?.detection_date || '').localeCompare(String(a?.detection_date || '')));
    } else {
      const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
      sorted.sort((a, b) => {
        const ra = rank[String(a?.risk?.risk_level || '').toLowerCase()] || 0;
        const rb = rank[String(b?.risk?.risk_level || '').toLowerCase()] || 0;
        return rb - ra;
      });
    }

    return sorted;
  }, [assets, activeTab, highRiskOnly, sortBy]);

  const pageSize = 10;
  const totalPages = Math.max(1, Math.ceil(discoveredRows.length / pageSize));
  const currentPage = Math.min(page, totalPages - 1);
  const pagedRows = discoveredRows.slice(currentPage * pageSize, (currentPage + 1) * pageSize);

  useEffect(() => {
    setPage(0);
  }, [activeTab, highRiskOnly, sortBy, assets.length]);

  const safeCount = assets.filter((a) => String(a?.risk?.risk_level || '').toLowerCase() === 'low').length;
  const partialCount = assets.filter((a) => String(a?.risk?.risk_level || '').toLowerCase() === 'medium').length;
  const vulnCount = assets.filter((a) => ['high', 'critical'].includes(String(a?.risk?.risk_level || '').toLowerCase())).length;

  const openWebsiteReport = (domain: string) => {
    window.open(`${apiBase}/api/reports/website/download?domain=${encodeURIComponent(domain)}&x_user_role=Super%20Admin`, '_blank');
  };

  return (
    <main className="md:ml-64 pt-16 min-h-screen p-8 space-y-8">
      <section className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 md:gap-0">
        <div>
          <h2 className="text-3xl font-extrabold tracking-tight text-on-surface headline-md">Asset Discovery</h2>
          <p className="text-on-surface-variant body-md mt-1">Real-time mapping of your organizational attack surface and cryptographic inventory.</p>
        </div>
        <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto">
          <button
            onClick={() => setHighRiskOnly((prev) => !prev)}
            className="px-4 py-2 bg-surface-container-highest text-on-surface rounded-lg text-sm font-semibold flex items-center gap-2 hover:bg-slate-300 transition-colors w-full sm:w-auto"
          >
            <span className="material-symbols-outlined text-sm flex items-center">filter_list</span>
            {highRiskOnly ? 'Show All Assets' : 'Show High Risk Only'}
          </button>
          <button
            onClick={() => window.open(apiBase + '/api/reports/asset-discovery/download?x_user_role=Super%20Admin', '_blank')}
            className="px-4 py-2 bg-gradient-to-br from-primary to-primary-container text-on-primary rounded-lg text-sm font-semibold flex items-center gap-2 w-full sm:w-auto"
          >
            <span className="material-symbols-outlined text-sm flex items-center">download</span>
            Export Inventory
          </button>
        </div>
      </section>

      <nav className="flex gap-8 border-b border-outline-variant/20 flex-wrap">
        {(['Domains', 'SSL Certificates', 'IP Addresses/Subnets', 'Software'] as DiscoveryTab[]).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`pb-4 text-sm transition-all w-full sm:w-auto ${activeTab === tab ? 'font-bold border-b-2 border-primary text-primary' : 'font-medium text-on-surface-variant hover:text-on-surface'}`}
          >
            {tab}
          </button>
        ))}
      </nav>

      <div className="grid grid-cols-12 gap-8 flex-col-reverse lg:flex-row">
        <div className="col-span-12 lg:col-span-8 bg-surface-container-lowest rounded-xl p-6 shadow-sm relative overflow-hidden h-[450px] flex flex-col border border-outline-variant/10">
          <div className="flex justify-between items-center mb-6">
            <h3 className="text-sm font-bold uppercase tracking-widest text-on-surface-variant">Entity Relationship Graph</h3>
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-tertiary"></span><span className="text-[10px] font-bold text-on-surface-variant">SAFE</span></div>
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-secondary-container"></span><span className="text-[10px] font-bold text-on-surface-variant">PARTIAL</span></div>
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-error"></span><span className="text-[10px] font-bold text-on-surface-variant">VULNERABLE</span></div>
            </div>
          </div>

          <div className="flex-1 relative bg-slate-50/50 rounded-lg border border-slate-100 overflow-hidden">
            {graphData.nodes.length > 0 ? (
              <ForceGraph2D
                width={820}
                height={350}
                graphData={graphData}
                nodeLabel={(n: any) => `${n.id} (${n.type || 'asset'})`}
                nodeColor={(n: any) => {
                  const risk = String(n?.risk || '').toLowerCase();
                  if (risk.includes('high') || risk.includes('critical')) return '#ba1a1a';
                  if (risk.includes('medium')) return '#f59e0b';
                  return '#006645';
                }}
                linkColor={() => '#cbd5e1'}
                linkDirectionalParticles={1}
                linkDirectionalParticleSpeed={0.004}
              />
            ) : (
              <div className="w-full h-full flex items-center justify-center text-xs text-on-surface-variant">No graph data available yet. Run scans to populate topology.</div>
            )}
          </div>
        </div>

        <div className="col-span-12 lg:col-span-4 space-y-4 overflow-hidden">
          <h3 className="text-sm font-bold uppercase tracking-widest text-on-surface-variant mb-2 px-1">Asset Distribution</h3>

          <div className="bg-surface-container-lowest p-3 sm:p-4 rounded-xl shadow-sm border border-outline-variant/10 flex items-center justify-between gap-2">
            <div>
              <p className="text-xs font-bold text-on-surface">Safe Assets</p>
              <p className="text-[10px] text-on-surface-variant">Low-risk discovered entities</p>
            </div>
            <span className="text-xs sm:text-sm font-extrabold text-tertiary truncate">{safeCount}</span>
          </div>

          <div className="bg-surface-container-lowest p-3 sm:p-4 rounded-xl shadow-sm border border-outline-variant/10 flex items-center justify-between gap-2">
            <div>
              <p className="text-xs font-bold text-on-surface">Partial Readiness</p>
              <p className="text-[10px] text-on-surface-variant">Medium-risk entities</p>
            </div>
            <span className="text-xs sm:text-sm font-extrabold text-secondary-container truncate min-w-[max-content]">{partialCount}</span>
          </div>

          <div className="bg-surface-container-lowest p-3 sm:p-4 rounded-xl shadow-sm border border-outline-variant/10 flex items-center justify-between gap-2">
            <div>
              <p className="text-xs font-bold text-on-surface">Vulnerable</p>
              <p className="text-[10px] text-on-surface-variant">High/Critical assets</p>
            </div>
            <span className="text-xs sm:text-sm font-extrabold text-error truncate">{vulnCount}</span>
          </div>
        </div>
      </div>

      <section className="bg-surface-container-lowest rounded-xl shadow-sm border border-outline-variant/10 overflow-hidden">
        <div className="px-6 py-4 border-b border-outline-variant/10 flex justify-between items-center bg-surface-container-low/30">
          <h3 className="text-sm font-bold text-on-surface">Discovered Domain Assets</h3>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">Sort by:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as 'Risk Level' | 'Discovery Date' | 'Alpha')}
              className="text-xs border-none bg-transparent focus:ring-0 font-bold text-primary cursor-pointer w-full sm:w-auto"
            >
              <option>Risk Level</option>
              <option>Discovery Date</option>
              <option>Alpha</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left min-w-[800px]">
            <thead>
              <tr className="bg-surface-container-low/50">
                <th className="px-6 py-3 text-[0.6875rem] font-bold uppercase tracking-widest text-on-surface-variant">Asset Name / Domain</th>
                <th className="px-6 py-3 text-[0.6875rem] font-bold uppercase tracking-widest text-on-surface-variant">IP Address</th>
                <th className="px-6 py-3 text-[0.6875rem] font-bold uppercase tracking-widest text-on-surface-variant">SSL Status</th>
                <th className="px-6 py-3 text-[0.6875rem] font-bold uppercase tracking-widest text-on-surface-variant">Discovery Type</th>
                <th className="px-6 py-3 text-[0.6875rem] font-bold uppercase tracking-widest text-on-surface-variant">Risk Score</th>
                <th className="px-6 py-3 text-[0.6875rem] font-bold uppercase tracking-widest text-on-surface-variant">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-outline-variant/5">
              {pagedRows.map((asset) => {
                const score = Number(asset?.risk?.score || 0);
                const ssl = asset?.scan_result?.certificate_issuer ? 'VALID' : 'UNKNOWN';
                const name = String(asset?.name || 'asset');
                const canOpenDomainReport = name.includes('.');
                return (
                  <tr key={asset.id} className="hover:bg-surface-container-low transition-colors group">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <span className="material-symbols-outlined text-primary text-sm flex items-center">language</span>
                        <div>
                          <p className="text-sm font-bold text-on-surface">{name}</p>
                          <p className="text-[10px] text-on-surface-variant">{asset?.type || 'Discovered Asset'}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-xs font-mono text-on-surface-variant">{asset?.ip_address || asset?.scan_result?.ipv4 || 'N/A'}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${ssl === 'VALID' ? 'bg-tertiary/10 text-tertiary border-tertiary/20' : 'bg-secondary-container/10 text-secondary-container border-secondary-container/20'}`}>
                        {ssl}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs font-medium text-on-surface">{asset?.metadata?.source || 'Active Probe'}</td>
                    <td className="px-6 py-4">
                      <div className="w-24 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                        <div className={`h-full ${score < 40 ? 'bg-error' : score < 70 ? 'bg-secondary-container' : 'bg-tertiary'}`} style={{ width: `${Math.max(4, 100 - score)}%` }}></div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => (canOpenDomainReport ? openWebsiteReport(name) : navigate('/scanner'))}
                        className="text-slate-400 hover:text-primary transition-colors"
                        title={canOpenDomainReport ? 'Open website report' : 'Open scanner'}
                      >
                        <span className="material-symbols-outlined text-sm flex items-center">open_in_new</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
              {pagedRows.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-sm text-on-surface-variant">No assets found for selected discovery tab/filter.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="px-6 py-4 bg-surface-container-low/30 border-t border-outline-variant/10 flex justify-between items-center">
          <p className="text-[10px] font-bold text-on-surface-variant">SHOWING {pagedRows.length} OF {discoveredRows.length} DISCOVERED ASSETS</p>
          <div className="flex gap-2">
            <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={currentPage === 0} className="p-1 rounded bg-white shadow-sm border border-outline-variant/10 text-slate-400 hover:text-primary disabled:opacity-40">
              <span className="material-symbols-outlined text-sm flex items-center">chevron_left</span>
            </button>
            <button onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))} disabled={currentPage >= totalPages - 1} className="p-1 rounded bg-white shadow-sm border border-outline-variant/10 text-slate-400 hover:text-primary disabled:opacity-40">
              <span className="material-symbols-outlined text-sm flex items-center">chevron_right</span>
            </button>
          </div>
        </div>
      </section>
    </main>
  );
};

export default AssetDiscovery;
