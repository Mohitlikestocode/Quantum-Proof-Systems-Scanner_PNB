import { useState, useEffect } from 'react';

const Cbom = () => {
  const [cbomData, setCbomData] = useState<any[]>([]);

  useEffect(() => {
    fetch((import.meta.env.VITE_API_URL || 'http://localhost:8010') + '/api/cbom')
      .then(res => res.json())
      .then(data => setCbomData(data))
      .catch(err => console.error("Failed to fetch CBOM", err));
  }, []);
  return (
    <main className="md:ml-64 mt-16 p-4 sm:p-6 md:p-8 bg-background min-h-screen">
      {/* Page Header */}
      <div className="mb-8 flex flex-col md:flex-row justify-between items-start md:items-end gap-4 md:gap-0">
        <div>
          <nav className="flex text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-2 gap-2">
            <span>Inventory</span>
            <span>/</span>
            <span className="text-primary">Cryptography Bill of Materials</span>
          </nav>
          <h2 className="text-3xl font-extrabold tracking-tight text-on-surface">CBOM Explorer</h2>
          <p className="text-on-surface-variant mt-1 text-sm max-w-2xl">Detailed inventory of cryptographic assets, quantum-safe readiness, and certificate hierarchies across the enterprise network.</p>
        </div>
        <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto">
          <button onClick={() => window.open((import.meta.env.VITE_API_URL || 'http://localhost:8010') + '/api/reports/download')} className="px-4 py-2 bg-surface-container-highest text-on-surface text-sm font-semibold rounded-lg hover:bg-slate-200 transition-colors flex items-center gap-2 w-full sm:w-auto">
            <span className="material-symbols-outlined text-[18px]">download</span> Export CBOM
          </button>
          <button onClick={() => alert("Asset Registration Flow initiated in new window")} className="px-4 py-2 bg-gradient-to-br from-primary to-primary-container text-white text-sm font-semibold rounded-lg shadow-sm flex items-center gap-2 w-full sm:w-auto">
            <span className="material-symbols-outlined text-[18px]">add</span> Register Asset
          </button>
        </div>
      </div>

      {/* Bento Grid: Top Charts & Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4 sm:gap-6 mb-8">
        {/* Metric 1: Key Length Distribution */}
        <div className="col-span-12 md:col-span-4 bg-surface-container-lowest rounded-xl p-6 shadow-sm">
          <div className="flex justify-between items-start mb-6">
            <h3 className="text-on-surface-variant font-bold text-[0.6875rem] uppercase tracking-wider">Key Length Distribution</h3>
            <span className="material-symbols-outlined text-slate-400 text-[20px]">info</span>
          </div>
          <div className="flex items-end gap-2 h-32 mb-4">
            <div className="flex-1 bg-surface-container-high rounded-t-sm relative group cursor-pointer" style={{ height: '45%' }}>
              <div className="absolute -top-6 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 text-[10px] font-bold bg-on-surface text-white px-1.5 py-0.5 rounded transition-opacity">1024</div>
            </div>
            <div className="flex-1 bg-secondary-container rounded-t-sm relative group cursor-pointer" style={{ height: '85%' }}>
              <div className="absolute -top-6 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 text-[10px] font-bold bg-on-surface text-white px-1.5 py-0.5 rounded transition-opacity">2048</div>
            </div>
            <div className="flex-1 bg-primary rounded-t-sm relative group cursor-pointer" style={{ height: '100%' }}>
              <div className="absolute -top-6 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 text-[10px] font-bold bg-on-surface text-white px-1.5 py-0.5 rounded transition-opacity">4096</div>
            </div>
            <div className="flex-1 bg-tertiary rounded-t-sm relative group cursor-pointer" style={{ height: '30%' }}>
              <div className="absolute -top-6 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 text-[10px] font-bold bg-on-surface text-white px-1.5 py-0.5 rounded transition-opacity">8192</div>
            </div>
          </div>
          <div className="flex justify-between text-[10px] font-bold text-slate-400">
            <span>1024-bit</span>
            <span>2048-bit</span>
            <span>4096-bit</span>
            <span>ECC</span>
          </div>
        </div>

        {/* Metric 2: Cipher Usage */}
        <div className="col-span-12 md:col-span-4 bg-surface-container-lowest rounded-xl p-6 shadow-sm">
          <div className="flex justify-between items-start mb-6">
            <h3 className="text-on-surface-variant font-bold text-[0.6875rem] uppercase tracking-wider">Cipher Usage Density</h3>
            <span className="material-symbols-outlined text-slate-400 text-[20px]">pie_chart</span>
          </div>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-xs font-bold mb-1.5">
                <span className="text-on-surface">AES-256-GCM</span>
                <span className="text-on-surface-variant">62%</span>
              </div>
              <div className="w-full h-1.5 bg-surface-container-high rounded-full overflow-hidden">
                <div className="h-full bg-primary" style={{ width: '62%' }}></div>
              </div>
            </div>
            <div>
              <div className="flex justify-between text-xs font-bold mb-1.5">
                <span className="text-on-surface">CHACHA20-POLY1305</span>
                <span className="text-on-surface-variant">24%</span>
              </div>
              <div className="w-full h-1.5 bg-surface-container-high rounded-full overflow-hidden">
                <div className="h-full bg-tertiary" style={{ width: '24%' }}></div>
              </div>
            </div>
            <div>
              <div className="flex justify-between text-xs font-bold mb-1.5">
                <span className="text-on-surface">RSA-PSS</span>
                <span className="text-on-surface-variant">14%</span>
              </div>
              <div className="w-full h-1.5 bg-surface-container-high rounded-full overflow-hidden">
                <div className="h-full bg-secondary-container" style={{ width: '14%' }}></div>
              </div>
            </div>
          </div>
        </div>

        {/* Metric 3: Top CAs */}
        <div className="col-span-12 md:col-span-4 bg-surface-container-lowest rounded-xl p-6 shadow-sm">
          <div className="flex justify-between items-start mb-4">
            <h3 className="text-on-surface-variant font-bold text-[0.6875rem] uppercase tracking-wider">Top Issuing CAs</h3>
            <span className="material-symbols-outlined text-slate-400 text-[20px]">verified</span>
          </div>
          <div className="space-y-3">
            <div className="flex items-center gap-3 p-2 rounded-lg bg-surface-container-low">
              <div className="w-8 h-8 flex items-center justify-center bg-white rounded border border-slate-100 overflow-hidden">
                <span className="material-symbols-outlined text-slate-400 text-sm">shield</span>
              </div>
              <div className="flex-1">
                <p className="text-[11px] font-bold text-on-surface leading-tight">DigiCert Global Root G2</p>
                <p className="text-[9px] text-slate-500 uppercase">342 Assets</p>
              </div>
              <span className="material-symbols-outlined text-tertiary text-sm" style={{ fontVariationSettings: "'FILL' 1" }}>check_circle</span>
            </div>
            <div className="flex items-center gap-3 p-2 rounded-lg bg-surface-container-low">
              <div className="w-8 h-8 flex items-center justify-center bg-white rounded border border-slate-100 overflow-hidden">
                <span className="material-symbols-outlined text-slate-400 text-sm">shield</span>
              </div>
              <div className="flex-1">
                <p className="text-[11px] font-bold text-on-surface leading-tight">Sectigo RSA Extended</p>
                <p className="text-[9px] text-slate-500 uppercase">128 Assets</p>
              </div>
              <span className="material-symbols-outlined text-tertiary text-sm" style={{ fontVariationSettings: "'FILL' 1" }}>check_circle</span>
            </div>
            <div className="flex items-center gap-3 p-2 rounded-lg bg-surface-container-low">
              <div className="w-8 h-8 flex items-center justify-center bg-white rounded border border-slate-100 overflow-hidden">
                <span className="material-symbols-outlined text-slate-400 text-sm">shield</span>
              </div>
              <div className="flex-1">
                <p className="text-[11px] font-bold text-on-surface leading-tight">R3 (Let's Encrypt)</p>
                <p className="text-[9px] text-slate-500 uppercase">86 Assets</p>
              </div>
              <span className="material-symbols-outlined text-tertiary text-sm" style={{ fontVariationSettings: "'FILL' 1" }}>check_circle</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Data Table Section */}
      <section className="bg-surface-container-lowest rounded-xl shadow-sm overflow-hidden flex flex-col">
        <div className="px-6 py-4 border-b border-surface-container-low flex flex-col sm:flex-row flex-wrap gap-4 items-start sm:items-center justify-between">
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 w-full sm:w-auto">
            <h3 className="font-bold text-on-surface text-sm">Algorithm Inventory</h3>
            <div className="flex items-center bg-surface-container-low rounded px-2 py-1 gap-2 border border-outline-variant/20">
              <span className="material-symbols-outlined text-slate-400 text-[18px]">search</span>
              <input className="bg-transparent border-none text-xs focus:ring-0 p-0 w-full sm:w-48 text-on-surface-variant placeholder:text-slate-400 outline-none" placeholder="Filter OID or Name..." type="text" />
            </div>
          </div>
          <div className="flex gap-2">
            <button className="p-1.5 hover:bg-surface-container-high rounded transition-colors text-on-surface-variant">
              <span className="material-symbols-outlined text-[20px]">tune</span>
            </button>
            <button className="p-1.5 hover:bg-surface-container-high rounded transition-colors text-on-surface-variant">
              <span className="material-symbols-outlined text-[20px]">refresh</span>
            </button>
          </div>
        </div>
        <div className="overflow-x-auto no-scrollbar w-full">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-container-low/50">
                <th className="px-6 py-3 font-bold text-[0.6875rem] uppercase tracking-[0.05em] text-on-surface-variant">Algorithm Name</th>
                <th className="px-6 py-3 font-bold text-[0.6875rem] uppercase tracking-[0.05em] text-on-surface-variant">Key Size / Curve</th>
                <th className="px-6 py-3 font-bold text-[0.6875rem] uppercase tracking-[0.05em] text-on-surface-variant">State</th>
                <th className="px-6 py-3 font-bold text-[0.6875rem] uppercase tracking-[0.05em] text-on-surface-variant">OID</th>
                <th className="px-6 py-3 font-bold text-[0.6875rem] uppercase tracking-[0.05em] text-on-surface-variant text-center">PQC Ready</th>
                <th className="px-6 py-3 font-bold text-[0.6875rem] uppercase tracking-[0.05em] text-on-surface-variant text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-container-low">
              {cbomData.map((item, index) => (
                <tr key={index} className="hover:bg-surface-container-low transition-colors group">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${item.state === 'Expired' || item.state === 'Vulnerable' ? 'bg-error' : item.pqc_ready ? 'bg-tertiary' : 'bg-primary'}`}></div>
                      <div>
                        <p className="text-sm font-bold text-on-surface">{item.algorithm_name}</p>
                        <p className="text-[10px] text-slate-500">{item.type}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-xs font-mono bg-surface-container-high px-2 py-0.5 rounded text-on-surface">{item.key_size}</span>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-tight ${item.state === 'Expired' || item.state === 'Vulnerable' ? 'bg-error/10 text-error' : item.state === 'Active' && item.pqc_ready ? 'bg-tertiary-container/10 text-tertiary' : 'bg-secondary-container/10 text-secondary'}`}>
                      {item.state}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-[11px] font-mono text-slate-500">{item.oid}</span>
                  </td>
                  <td className="px-6 py-4 text-center">
                    {item.pqc_ready ? (
                      <span className="material-symbols-outlined text-tertiary" style={{ fontVariationSettings: "'FILL' 1" }}>verified</span>
                    ) : item.state === 'Expired' ? (
                      <span className="material-symbols-outlined text-error" style={{ fontVariationSettings: "'FILL' 1" }}>dangerous</span>
                    ) : (
                      <span className="material-symbols-outlined text-slate-300">hourglass_empty</span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button className="text-slate-400 hover:text-primary transition-colors">
                      <span className="material-symbols-outlined text-[18px]">more_vert</span>
                    </button>
                  </td>
                </tr>
              ))}
              {cbomData.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-on-surface-variant text-sm">No CBOM data found.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        
        <div className="px-6 py-4 border-t border-surface-container-low flex items-center justify-between text-xs text-on-surface-variant font-medium">
          <p>Showing 5 of 142 detected cryptographic assets</p>
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 w-full sm:w-auto">
            <div className="flex items-center gap-1">
              <button className="w-8 h-8 flex items-center justify-center rounded hover:bg-surface-container-high disabled:opacity-30" disabled>
                <span className="material-symbols-outlined text-[20px]">chevron_left</span>
              </button>
              <button className="w-8 h-8 flex items-center justify-center rounded bg-primary text-white font-bold">1</button>
              <button className="w-8 h-8 flex items-center justify-center rounded hover:bg-surface-container-high">2</button>
              <button className="w-8 h-8 flex items-center justify-center rounded hover:bg-surface-container-high">3</button>
              <button className="w-8 h-8 flex items-center justify-center rounded hover:bg-surface-container-high">
                <span className="material-symbols-outlined text-[20px]">chevron_right</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Technical Metadata Sidebar / Detail View Placeholder */}
      <div className="mt-8 grid grid-cols-1 md:grid-cols-12 gap-4 sm:gap-6">
        <div className="col-span-12 lg:col-span-8 bg-surface-container-lowest rounded-xl p-6 shadow-sm border border-outline-variant/5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-bold text-on-surface text-sm">Certificate Dependency Chain</h3>
            <span className="text-[10px] font-bold text-primary uppercase">Live Graph View</span>
          </div>
          {/* Node Map visualization placeholder */}
          <div className="relative h-64 bg-surface-container-low rounded-lg border border-dashed border-outline-variant/30 flex items-center justify-center overflow-hidden">
            <div className="absolute inset-0 opacity-10" style={{ backgroundImage: 'radial-gradient(#0054d6 0.5px, transparent 0.5px)', backgroundSize: '20px 20px' }}></div>
            <div className="relative z-10 flex flex-col items-center gap-4">
              <div className="flex items-center gap-8">
                <div className="w-16 h-16 rounded-full bg-white border-2 border-primary flex items-center justify-center shadow-lg relative">
                  <span className="material-symbols-outlined text-primary">hub</span>
                  <div className="absolute -bottom-1 -right-1 w-5 h-5 bg-tertiary rounded-full border-2 border-white flex items-center justify-center text-[10px] text-white">4</div>
                </div>
                <div className="w-12 h-px bg-primary opacity-30"></div>
                <div className="w-12 h-12 rounded-lg bg-white border border-outline-variant flex items-center justify-center shadow-sm">
                  <span className="material-symbols-outlined text-slate-400">cloud_done</span>
                </div>
                <div className="w-12 h-px bg-primary opacity-30"></div>
                <div className="w-12 h-12 rounded-lg bg-white border border-outline-variant flex items-center justify-center shadow-sm">
                  <span className="material-symbols-outlined text-slate-400">account_balance</span>
                </div>
              </div>
              <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Select an algorithm to visualize its impact surface</p>
            </div>
          </div>
        </div>
        
        <div className="col-span-12 lg:col-span-4 space-y-6">
          <div className="bg-primary text-white rounded-xl p-6 shadow-lg shadow-primary/10 relative overflow-hidden">
            <div className="absolute top-0 right-0 w-32 h-32 bg-white/10 rounded-full blur-3xl -mr-16 -mt-16"></div>
            <div className="relative z-10">
              <h4 className="text-sm font-bold mb-2">PQC Readiness Task</h4>
              <p className="text-xs text-white/80 leading-relaxed mb-4">Your infrastructure contains 3 legacy SHA-1 and 12 RSA-1024 assets that must be rotated within 90 days to meet compliance.</p>
              <button className="w-full bg-white text-primary py-2 rounded-lg text-xs font-bold hover:bg-slate-100 transition-colors">Generate Remediation Plan</button>
            </div>
          </div>
          
          <div className="bg-surface-container-lowest rounded-xl p-6 shadow-sm border border-outline-variant/5">
            <h4 className="font-bold text-on-surface text-sm mb-4">Scanner Statistics</h4>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs text-on-surface-variant font-medium">Last Scan</span>
                <span className="text-xs font-bold text-on-surface">14 mins ago</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-on-surface-variant font-medium">Total OIDs Scanned</span>
                <span className="text-xs font-bold text-on-surface">4,281</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-on-surface-variant font-medium">Unique Entities</span>
                <span className="text-xs font-bold text-on-surface">192</span>
              </div>
              <div className="pt-2">
                <div className="h-1 w-full bg-surface-container-low rounded-full">
                  <div className="h-full bg-tertiary w-[88%] rounded-full"></div>
                </div>
                <p className="text-[9px] font-bold text-slate-400 mt-2 uppercase">Compliance Integrity: 88%</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
};

export default Cbom;
