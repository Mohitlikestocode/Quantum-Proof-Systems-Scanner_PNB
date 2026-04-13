import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

type RiskSummary = {
  total_assets: number;
  apis: number;
  servers: number;
  expiring_certs: number;
  high_risk: number;
  medium_risk: number;
  low_risk: number;
  pqc_readiness_pct: number;
};

const Dashboard = () => {
  const navigate = useNavigate();
  const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8010';
  const [summary, setSummary] = useState<RiskSummary>({
    total_assets: 0,
    apis: 0,
    servers: 0,
    expiring_certs: 0,
    high_risk: 0,
    medium_risk: 0,
    low_risk: 0,
    pqc_readiness_pct: 0,
  });
  const [heatmap, setHeatmap] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);

  useEffect(() => {
    fetch(apiBase + '/api/risk')
      .then((res) => res.json())
      .then((data) => {
        if (data?.summary) {
          setSummary(data.summary);
          setHeatmap(data.heatmap || []);
        }
      })
      .catch((err) => console.error('Failed to fetch risk metrics', err));

    fetch(apiBase + '/api/assets')
      .then((res) => res.json())
      .then((data) => setAssets(Array.isArray(data) ? data : []))
      .catch((err) => console.error('Failed to fetch assets', err));
  }, [apiBase]);

  const riskTrend = useMemo(() => {
    const base = Math.max(summary.total_assets, 1);
    return [summary.high_risk, summary.medium_risk, summary.low_risk, summary.expiring_certs, summary.apis, summary.servers, summary.total_assets]
      .map((value) => Math.max(10, Math.min(100, Math.round((value / base) * 100))));
  }, [summary]);

  const recentAssets = useMemo(() => assets.slice(0, 8), [assets]);

  return (
    <main className="md:ml-64 pt-24 pb-12 px-8" id="inventory">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-on-surface">Security Overview</h2>
          <p className="text-on-surface-variant text-sm mt-1">Live cryptographic asset monitoring and risk assessment.</p>
        </div>
        <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto">
          <button onClick={() => window.location.reload()} className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-white text-on-surface border border-outline-variant rounded hover:bg-surface-container-low transition-colors w-full sm:w-auto">
            <span className="material-symbols-outlined text-[18px]" data-icon="refresh">refresh</span>
            Refresh
          </button>
          <button
            onClick={() => window.open(apiBase + '/api/reports/download?x_user_role=Super%20Admin', '_blank')}
            className="flex items-center justify-center gap-2 px-6 py-2.5 bg-gradient-to-br from-primary to-primary-container text-white rounded-lg text-sm font-bold shadow-md shadow-primary/20 hover:scale-105 active:scale-95 transition-all"
          >
            <span className="material-symbols-outlined text-[18px]" data-icon="download">download</span>
            Export Complete Report
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-6 mb-8">
        <div className="bg-surface-container-lowest p-5 rounded-xl border border-outline-variant/10 shadow-sm">
          <p className="text-[10px] font-bold text-on-surface-variant uppercase tracking-wider mb-3">Total Assets</p>
          <span className="text-2xl font-bold text-on-surface tracking-tight">{summary.total_assets}</span>
        </div>
        <div className="bg-surface-container-lowest p-5 rounded-xl border border-outline-variant/10 shadow-sm">
          <p className="text-[10px] font-bold text-on-surface-variant uppercase tracking-wider mb-3">APIs</p>
          <span className="text-2xl font-bold text-on-surface tracking-tight">{summary.apis}</span>
        </div>
        <div className="bg-surface-container-lowest p-5 rounded-xl border border-outline-variant/10 shadow-sm">
          <p className="text-[10px] font-bold text-on-surface-variant uppercase tracking-wider mb-3">Servers</p>
          <span className="text-2xl font-bold text-on-surface tracking-tight">{summary.servers}</span>
        </div>
        <div className="bg-surface-container-lowest p-5 rounded-xl border border-outline-variant/10 shadow-sm">
          <p className="text-[10px] font-bold text-on-surface-variant uppercase tracking-wider mb-3">Expiring Certs</p>
          <span className="text-2xl font-bold text-secondary-container tracking-tight">{summary.expiring_certs}</span>
        </div>
        <div className="bg-surface-container-lowest p-5 rounded-xl border border-outline-variant/10 shadow-sm">
          <p className="text-[10px] font-bold text-on-surface-variant uppercase tracking-wider mb-3">PQC Ready</p>
          <span className="text-2xl font-bold text-tertiary tracking-tight">{summary.pqc_readiness_pct}%</span>
        </div>
        <div className="bg-surface-container-lowest p-5 rounded-xl border border-outline-variant/10 shadow-sm ring-2 ring-error/5">
          <p className="text-[10px] font-bold text-error uppercase tracking-wider mb-3">High Risk Assets</p>
          <span className="text-2xl font-bold text-error tracking-tight">{summary.high_risk}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 mb-8">
        <div className="col-span-12 lg:col-span-8 bg-surface-container-lowest p-6 rounded-xl shadow-sm">
          <h3 className="text-sm font-bold text-on-surface tracking-tight uppercase mb-6">Quantum Vulnerability Heatmap</h3>
          <div className="grid grid-cols-10 gap-1.5">
            {heatmap.slice(0, 50).map((item, index) => {
              const risk = String(item?.risk || '').toLowerCase();
              const colorClass = risk.includes('high') || risk.includes('critical') ? 'bg-error/80' : risk.includes('medium') ? 'bg-secondary-container/80' : 'bg-tertiary/60';
              return <div key={`${item.asset_name}-${index}`} className={`rounded-sm w-full h-[32px] ${colorClass}`} title={`${item.asset_name}: ${item.algorithm} / ${item.tls_version}`}></div>;
            })}
            {[...Array(Math.max(0, 50 - heatmap.length))].map((_, i) => <div key={`empty-${i}`} className="bg-surface-container-high/30 rounded-sm w-full h-[32px]"></div>)}
          </div>
        </div>

        <div className="col-span-12 lg:col-span-4 bg-surface-container-lowest p-6 rounded-xl shadow-sm">
          <h3 className="text-sm font-bold text-on-surface tracking-tight uppercase mb-6">Risk Profile Trend</h3>
          <div className="h-40 flex items-end gap-2">
            {riskTrend.map((height, idx) => (
              <div key={idx} className={`${idx % 2 === 0 ? 'bg-primary' : 'bg-surface-container-high'} flex-1 rounded-t-sm`} style={{ height: `${height}%` }}></div>
            ))}
          </div>
          <div className="flex justify-between mt-4 text-[10px] font-bold text-on-surface-variant">
            <span>H</span><span>M</span><span>L</span><span>CERT</span><span>API</span><span>SRV</span><span>ALL</span>
          </div>
        </div>
      </div>

      <div className="bg-surface-container-lowest rounded-xl shadow-sm overflow-hidden">
        <div className="p-6 flex justify-between items-center border-b border-outline-variant/5">
          <h3 className="text-sm font-bold text-on-surface tracking-tight uppercase">Recent Asset Inventory</h3>
          <button onClick={() => window.open(apiBase + '/api/assets', '_blank')} className="text-primary text-[10px] font-bold uppercase tracking-widest hover:underline w-full sm:w-auto">View All Assets</button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-surface-container-low">
              <tr>
                <th className="px-6 py-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-wider">Domain / IP</th>
                <th className="px-6 py-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-wider">Type</th>
                <th className="px-6 py-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-wider text-center">Risk</th>
                <th className="px-6 py-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-wider">TLS</th>
                <th className="px-6 py-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-wider">Key / Algo</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-outline-variant/5">
              {recentAssets.length === 0 ? (
                <tr><td className="px-6 py-4 text-sm text-on-surface-variant" colSpan={5}>No assets scanned yet.</td></tr>
              ) : recentAssets.map((asset) => {
                const scan = asset.scan_result || {};
                const risk = String(asset?.risk?.risk_level || '').toLowerCase();
                const dotClass = risk.includes('high') || risk.includes('critical') ? 'bg-error animate-pulse' : risk.includes('medium') ? 'bg-secondary-container' : 'bg-tertiary';
                return (
                  <tr
                    key={asset.id}
                    onClick={() => {
                      const assetName = String(asset?.name || '');
                      if (assetName.includes('.')) {
                        window.open(apiBase + '/api/reports/website/download?domain=' + encodeURIComponent(assetName) + '&x_user_role=Super%20Admin', '_blank');
                        return;
                      }
                      navigate('/asset-inventory');
                    }}
                    className="hover:bg-surface-container-low transition-colors cursor-pointer"
                  >
                    <td className="px-6 py-4">
                      <p className="text-xs font-bold text-on-surface">{asset.name}</p>
                      <p className="text-[10px] text-slate-400">{asset.ip_address || scan.ipv4 || 'N/A'}</p>
                    </td>
                    <td className="px-6 py-4">
                      <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px] font-bold uppercase">{asset.type || 'Asset'}</span>
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className={`w-2 h-2 rounded-full inline-block ${dotClass}`}></span>
                    </td>
                    <td className="px-6 py-4 text-[11px] font-medium">{scan.tls_version || 'Unknown'}</td>
                    <td className="px-6 py-4 text-[11px] font-mono text-slate-500">{scan.algorithm || 'N/A'} {scan.key_size || ''}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
};

export default Dashboard;
