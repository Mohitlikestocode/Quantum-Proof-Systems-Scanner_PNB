import { useState, useEffect } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { useNavigate } from 'react-router-dom';

const AssetInventory = () => {
  const navigate = useNavigate();
  const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8010';
  const [assets, setAssets] = useState<any[]>([]);
  const [graphData, setGraphData] = useState<{nodes: any[], links: any[]}>({ nodes: [], links: [] });
  const [filterType, setFilterType] = useState("Asset Type");
  const [filterStatus, setFilterStatus] = useState("Status");
  const [filterRisk, setFilterRisk] = useState("Risk Level");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);

  useEffect(() => {
    fetch(apiBase + '/api/assets')
      .then(res => res.json())
      .then(data => setAssets(data))
      .catch(err => console.error("Failed to fetch assets", err));

    fetch(apiBase + '/api/graph')
      .then(res => res.json())
      .then(data => {
        // Need to format links for force graph (source/target)
        let formattedData = {
           nodes: data.nodes || [],
           links: (data.edges || []).map((e: any) => ({ source: e.source, target: e.target }))
        };
        setGraphData(formattedData);
      })
      .catch(err => console.error("Failed to fetch graph data", err));
  }, [apiBase]);

  const filteredAssets = assets.filter(a => {
    if (search && !a.name.toLowerCase().includes(search.toLowerCase()) && !(a.ip_address && a.ip_address.includes(search))) return false;
    if (filterType !== "Asset Type" && a.type !== filterType) return false;
    if (filterStatus !== "Status" && a.scan_result && a.risk) {
        if (filterStatus === "Safe" && a.risk.risk_level !== "Low") return false;
        if (filterStatus === "Warning" && a.risk.risk_level !== "Medium") return false;
        if (filterStatus === "Critical" && a.risk.risk_level !== "High") return false;
    }
    if (filterRisk !== "Risk Level" && a.risk && a.risk.risk_level !== filterRisk) return false;
    return true;
  });

  const pageSize = 20;
  const totalPages = Math.max(1, Math.ceil(filteredAssets.length / pageSize));
  const currentPage = Math.min(page, totalPages - 1);
  const pagedAssets = filteredAssets.slice(currentPage * pageSize, (currentPage + 1) * pageSize);

  useEffect(() => {
    setPage(0);
  }, [filterType, filterStatus, filterRisk, search, assets.length]);

  return (
    <main className="md:ml-64 pt-24 pb-12 px-8">
      {/* Header Section */}
      <div className="mb-10">
        <h1 className="text-[1.75rem] font-bold text-on-surface leading-tight tracking-tight headline-md">Asset Inventory</h1>
        <p className="text-on-surface-variant body-md mt-1">Comprehensive visibility into all network infrastructure and software components.</p>
      </div>

      {/* Bento Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
        <div className="bg-surface-container-lowest p-6 rounded-xl border-l-4 border-primary shadow-sm hover:shadow-md transition-shadow">
          <div className="flex justify-between items-start mb-2">
            <span className="text-on-surface-variant text-[0.6875rem] font-bold uppercase tracking-wider label-sm">Total Assets</span>
            <span className="material-symbols-outlined text-primary opacity-60" data-icon="inventory">inventory</span>
          </div>
          <div className="text-3xl font-bold text-on-surface display-lg">{assets.length > 0 ? assets.length : '0'}</div>
          <div className="mt-4 flex items-center text-tertiary text-xs font-semibold">
            <span className="material-symbols-outlined text-xs mr-1" data-icon="trending_up">trending_up</span>
            +12% from last month
          </div>
        </div>

        <div className="bg-surface-container-lowest p-6 rounded-xl border-l-4 border-secondary shadow-sm hover:shadow-md transition-shadow">
          <div className="flex justify-between items-start mb-2">
            <span className="text-on-surface-variant text-[0.6875rem] font-bold uppercase tracking-wider label-sm">Managed Assets</span>
            <span className="material-symbols-outlined text-secondary opacity-60" data-icon="admin_panel_settings">admin_panel_settings</span>
          </div>
          <div className="text-3xl font-bold text-on-surface display-lg">{assets.filter(a => a.status === 'confirmed').length}</div>
          <div className="mt-4 text-on-surface-variant text-xs font-medium">
            86.2% of total fleet
          </div>
        </div>

        <div className="bg-surface-container-lowest p-6 rounded-xl border-l-4 border-outline shadow-sm hover:shadow-md transition-shadow">
          <div className="flex justify-between items-start mb-2">
            <span className="text-on-surface-variant text-[0.6875rem] font-bold uppercase tracking-wider label-sm">Shadow Assets</span>
            <span className="material-symbols-outlined text-outline opacity-60" data-icon="visibility_off">visibility_off</span>
          </div>
          <div className="text-3xl font-bold text-on-surface display-lg">{assets.filter(a => a.status !== 'confirmed').length}</div>
          <div className="mt-4 flex items-center text-error text-xs font-semibold">
            <span className="material-symbols-outlined text-xs mr-1" data-icon="warning">warning</span>
            Requires immediate audit
          </div>
        </div>

        <div className="bg-surface-container-lowest p-6 rounded-xl border-l-4 border-error shadow-sm hover:shadow-md transition-shadow">
          <div className="flex justify-between items-start mb-2">
            <span className="text-on-surface-variant text-[0.6875rem] font-bold uppercase tracking-wider label-sm">High Risk</span>
            <span className="material-symbols-outlined text-error opacity-60" data-icon="report">report</span>
          </div>
          <div className="text-3xl font-bold text-on-surface display-lg">{assets.filter(a => a.risk?.risk_level === 'High').length}</div>
          <div className="mt-4 flex items-center text-error text-xs font-semibold">
            <span className="material-symbols-outlined text-xs mr-1" data-icon="priority_high">priority_high</span>
            Across 3 critical nodes
          </div>
        </div>
      </div>

      {/* Filters and Table Card */}
      <div className="bg-surface-container-lowest rounded-xl shadow-sm overflow-hidden flex flex-col min-h-[600px] mb-6">
        {/* Filter Bar */}
        <div className="p-4 bg-surface-container-low flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="relative">
              <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-sm" data-icon="search">search</span>
              <input value={search} onChange={(e) => setSearch(e.target.value)} className="bg-white border text-slate-800 border-outline-variant/30 rounded-lg py-2 pl-10 pr-4 text-sm w-80 focus:ring-2 focus:ring-primary/20 focus:border-primary" placeholder="Filter assets by name, IP, or vendor..." type="text" />
            </div>
            <div className="flex gap-2 text-slate-800">
              <select value={filterType} onChange={(e) => setFilterType(e.target.value)} className="bg-white border outline-none border-outline-variant/30 rounded-lg py-2 pl-3 pr-8 text-sm focus:ring-2 focus:ring-primary/20 text-on-surface-variant font-medium">
                <option>Asset Type</option>
                <option>Hardware</option>
                <option>Software</option>
                <option>Domain</option>
              </select>
              <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} className="bg-white border outline-none border-outline-variant/30 rounded-lg py-2 pl-3 pr-8 text-sm focus:ring-2 focus:ring-primary/20 text-on-surface-variant font-medium">
                <option>Status</option>
                <option>Safe</option>
                <option>Warning</option>
                <option>Critical</option>
              </select>
              <select value={filterRisk} onChange={(e) => setFilterRisk(e.target.value)} className="bg-white border outline-none border-outline-variant/30 rounded-lg py-2 pl-3 pr-8 text-sm focus:ring-2 focus:ring-primary/20 text-on-surface-variant font-medium">
                <option>Risk Level</option>
                <option>Low</option>
                <option>Medium</option>
                <option>High</option>
              </select>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => window.open(apiBase + '/api/reports/download')} className="bg-surface-container-highest text-on-surface px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2 hover:bg-surface-variant transition-colors border border-outline-variant/20 w-full sm:w-auto">
              <span className="material-symbols-outlined text-sm" data-icon="file_download">file_download</span>
              Export
            </button>
            <button onClick={() => navigate('/scanner')} className="bg-gradient-to-br from-primary to-primary-container text-white px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2 hover:opacity-90 transition-opacity w-full sm:w-auto">
              <span className="material-symbols-outlined text-sm" data-icon="add">add</span>
              Add Asset
            </button>
          </div>
        </div>

        {/* Data Table */}
        <div className="flex-1 overflow-x-auto no-scrollbar">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-container-low border-b border-outline-variant/10">
                <th className="px-6 py-4 text-[0.6875rem] font-bold uppercase tracking-wider text-on-surface-variant label-sm">Asset Name</th>
                <th className="px-6 py-4 text-[0.6875rem] font-bold uppercase tracking-wider text-on-surface-variant label-sm">Status</th>
                <th className="px-6 py-4 text-[0.6875rem] font-bold uppercase tracking-wider text-on-surface-variant label-sm">Type</th>
                <th className="px-6 py-4 text-[0.6875rem] font-bold uppercase tracking-wider text-on-surface-variant label-sm">Region</th>
                <th className="px-6 py-4 text-[0.6875rem] font-bold uppercase tracking-wider text-on-surface-variant label-sm">IP Address</th>
                <th className="px-6 py-4 text-[0.6875rem] font-bold uppercase tracking-wider text-on-surface-variant label-sm">Vendor</th>
                <th className="px-6 py-4 text-[0.6875rem] font-bold uppercase tracking-wider text-on-surface-variant label-sm text-right">Risk Level</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-outline-variant/10">
              {pagedAssets.map(asset => {
                const isHigh = asset.risk?.risk_level === 'High';
                const isMedium = asset.risk?.risk_level === 'Medium';
                
                return (
                  <tr
                    key={asset.id}
                    onClick={() => {
                      const assetName = String(asset?.name || '');
                      if (assetName.includes('.')) {
                        window.open(apiBase + '/api/reports/website/download?domain=' + encodeURIComponent(assetName) + '&x_user_role=Super%20Admin', '_blank');
                        return;
                      }
                      navigate('/scanner');
                    }}
                    className="hover:bg-surface-container-low transition-colors group cursor-pointer"
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className={`w-8 h-8 rounded ${isHigh ? 'bg-error/10' : isMedium ? 'bg-secondary/10' : 'bg-primary/10'} flex items-center justify-center`}>
                          <span className={`material-symbols-outlined ${isHigh ? 'text-error' : isMedium ? 'text-secondary' : 'text-primary'} text-lg`} data-icon="dns">dns</span>
                        </div>
                        <div>
                          <div className="font-semibold text-on-surface text-sm">{asset.name}</div>
                          <div className="text-xs text-on-surface-variant">{asset.type}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${isHigh ? 'bg-error-container text-on-error-container' : isMedium ? 'bg-secondary-container/20 text-secondary' : 'bg-tertiary-container text-on-tertiary-container'}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${isHigh ? 'bg-error' : isMedium ? 'bg-secondary' : 'bg-tertiary'} mr-1.5`}></span>
                        {asset.risk?.status || 'Unknown'}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-on-surface-variant">{asset.type}</td>
                    <td className="px-6 py-4 text-sm text-on-surface-variant">{asset.region}</td>
                    <td className="px-6 py-4 text-sm font-mono text-on-surface-variant">{asset.ip_address || '-'}</td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <span className="material-symbols-outlined text-sm text-slate-500" data-icon="cloud">cloud</span>
                        <span className="text-sm text-on-surface-variant">{asset.vendor}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <div className="w-16 h-1.5 bg-surface-container-high rounded-full overflow-hidden">
                          <div className={`h-full ${isHigh ? 'bg-error' : isMedium ? 'bg-secondary-container' : 'bg-tertiary'} rounded-full`} style={{ width: `${100 - (asset.risk?.score || 0)}%` }}></div>
                        </div>
                        <span className={`text-xs font-bold ${isHigh ? 'text-error' : isMedium ? 'text-secondary' : 'text-tertiary'}`}>{asset.risk?.score || 0}%</span>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {pagedAssets.length === 0 && (
                <tr>
                    <td colSpan={7} className="px-6 py-8 text-center text-sm text-on-surface-variant">No assets found matching criteria.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="px-6 py-4 border-t border-outline-variant/10 flex items-center justify-between bg-surface-container-low">
            Showing {pagedAssets.length} of {filteredAssets.length} assets
          <div className="flex gap-1">
            <button
              onClick={() => setPage((prev) => Math.max(0, prev - 1))}
              disabled={currentPage === 0}
              className="w-8 h-8 flex items-center justify-center rounded border border-outline-variant/30 text-on-surface-variant hover:bg-white transition-colors disabled:opacity-40"
            >
              <span className="material-symbols-outlined text-sm" data-icon="chevron_left">chevron_left</span>
            </button>
            <button className="w-8 h-8 flex items-center justify-center rounded bg-primary text-white text-xs font-bold">{currentPage + 1}</button>
            <button
              onClick={() => setPage((prev) => Math.min(totalPages - 1, prev + 1))}
              disabled={currentPage >= totalPages - 1}
              className="w-8 h-8 flex items-center justify-center rounded border border-outline-variant/30 text-on-surface-variant hover:bg-white transition-colors disabled:opacity-40"
            >
              <span className="material-symbols-outlined text-sm" data-icon="chevron_right">chevron_right</span>
            </button>
          </div>
        </div>
      </div>

      {/* Contextual Insights Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">
        <div className="lg:col-span-2 bg-surface-container-lowest p-6 rounded-xl shadow-sm border border-outline-variant/5">
          <div className="flex justify-between items-center mb-6">
            <h3 className="font-bold text-on-surface text-base">Interactive Network Topology</h3>
            <div className="flex gap-2">
               <span className="flex items-center gap-1 text-[10px] uppercase font-bold text-slate-500"><div className="w-2 h-2 rounded-full bg-error"></div> High</span>
               <span className="flex items-center gap-1 text-[10px] uppercase font-bold text-slate-500"><div className="w-2 h-2 rounded-full bg-secondary"></div> Medium</span>
               <span className="flex items-center gap-1 text-[10px] uppercase font-bold text-slate-500"><div className="w-2 h-2 rounded-full bg-tertiary"></div> Low</span>
            </div>
          </div>
          <div className="h-48 w-full bg-surface-container-low rounded-lg border border-outline-variant/10 overflow-hidden relative">
             <div className="absolute inset-0 opacity-10 pointer-events-none" style={{ backgroundImage: 'radial-gradient(#0054d6 0.5px, transparent 0.5px)', backgroundSize: '15px 15px' }}></div>
             {graphData.nodes.length > 0 ? (
                 <ForceGraph2D
                    width={800}
                    height={200}
                    graphData={graphData}
                    nodeRelSize={6}
                    nodeColor={(node: any) => node.risk === 'High' ? '#D92D20' : node.risk === 'Medium' ? '#F79009' : '#12B76A'}
                    linkColor={() => '#E2E8F0'}
                    nodeLabel={(node: any) => `${node.id} (${node.type})`}
                    linkDirectionalParticles={2}
                    linkDirectionalParticleSpeed={0.005}
                 />
             ) : (
                <div className="w-full h-full flex items-center justify-center text-xs font-medium text-slate-400">Loading graph data...</div>
             )}
          </div>
        </div>

        <div className="bg-gradient-to-br from-primary to-primary-container p-6 rounded-xl shadow-lg relative overflow-hidden group">
          <div className="absolute -right-4 -top-4 w-24 h-24 bg-white/10 rounded-full blur-2xl group-hover:scale-150 transition-transform duration-700"></div>
          <h3 className="text-white font-bold text-base mb-2 relative z-10">Automated Discovery</h3>
          <p className="text-blue-100 text-xs leading-relaxed mb-6 relative z-10">Discovery agents identified 14 new endpoints in the last 24 hours. Would you like to categorize them now?</p>
          <button onClick={() => navigate('/asset-discovery')} className="w-full py-2.5 bg-white text-primary text-xs font-bold rounded-lg hover:bg-blue-50 transition-colors shadow-sm relative z-10">Review New Assets</button>
          <div className="mt-4 pt-4 border-t border-white/10 relative z-10">
            <div className="flex items-center gap-2 text-[10px] font-bold text-blue-200 uppercase tracking-widest">
              <span className="material-symbols-outlined text-xs" data-icon="sync">sync</span>
              Next scan in 14m 22s
            </div>
          </div>
        </div>
      </div>
    </main>
  );
};

export default AssetInventory;
