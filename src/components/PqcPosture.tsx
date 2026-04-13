import { useNavigate } from 'react-router-dom';

const PqcPosture = () => {
  const navigate = useNavigate();
  const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8010';
  return (
    <main className="md:ml-64 pt-24 px-8 pb-12 min-h-screen">
      <header className="mb-8">
        <h2 className="text-[1.75rem] font-bold text-on-surface tracking-tight leading-none mb-1">PQC Posture</h2>
        <p className="text-on-surface-variant text-sm">Real-time cryptographic readiness and algorithm transition status.</p>
      </header>
      
      {/* Summary Metrics & Bento Grid */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4 sm:gap-6 mb-8">
        {/* Hero Metric */}
        <div className="col-span-12 lg:col-span-4 bg-surface-container-lowest p-8 rounded-xl shadow-sm border border-outline-variant/10 flex flex-col justify-between">
          <div>
            <span className="text-[0.6875rem] uppercase tracking-wider font-bold text-on-surface-variant">Fleet Readiness</span>
            <div className="flex items-baseline gap-2 mt-4">
              <span className="text-[3.5rem] font-extrabold text-primary leading-tight">92.4</span>
              <span className="text-xl font-bold text-primary/60">%</span>
            </div>
          </div>
          <div className="mt-8">
            <div className="w-full bg-surface-container-high h-2 rounded-full overflow-hidden">
              <div className="bg-gradient-to-r from-primary to-primary-container h-full" style={{ width: '92.4%' }}></div>
            </div>
            <p className="text-[0.6875rem] mt-3 text-tertiary font-medium flex items-center gap-1">
              <span className="material-symbols-outlined text-sm" data-icon="trending_up">trending_up</span>
              +2.1% from last audit
            </p>
          </div>
        </div>
        
        {/* Status Distribution */}
        <div className="col-span-12 lg:col-span-8 grid grid-cols-3 gap-6">
          <div className="bg-surface-container-lowest p-6 rounded-xl shadow-sm border border-outline-variant/10 flex flex-col items-start justify-between">
            <span className="text-[0.6875rem] uppercase tracking-wider font-bold text-on-surface-variant block mb-6">Standard</span>
            <div>
              <span className="text-2xl font-bold text-on-surface">1,248</span>
              <p className="text-xs text-on-surface-variant mt-1">Compliant Assets</p>
              <div className="mt-4 py-1 px-2 bg-tertiary/10 text-tertiary text-[0.625rem] font-bold rounded inline-block">SECURE</div>
            </div>
          </div>
          <div className="bg-surface-container-lowest p-6 rounded-xl shadow-sm border border-outline-variant/10 flex flex-col items-start justify-between">
            <span className="text-[0.6875rem] uppercase tracking-wider font-bold text-on-surface-variant block mb-6">Legacy</span>
            <div>
              <span className="text-2xl font-bold text-on-surface">142</span>
              <p className="text-xs text-on-surface-variant mt-1">Transitioning</p>
              <div className="mt-4 py-1 px-2 bg-secondary-container/10 text-secondary text-[0.625rem] font-bold rounded inline-block">WARNING</div>
            </div>
          </div>
          <div className="bg-surface-container-lowest p-6 rounded-xl shadow-sm border border-outline-variant/10 flex flex-col items-start justify-between">
            <span className="text-[0.6875rem] uppercase tracking-wider font-bold text-on-surface-variant block mb-6">Critical</span>
            <div>
              <span className="text-2xl font-bold text-error">12</span>
              <p className="text-xs text-on-surface-variant mt-1">High Vulnerability</p>
              <div className="mt-4 py-1 px-2 bg-error/10 text-error text-[0.625rem] font-bold rounded inline-block">DANGER</div>
            </div>
          </div>
        </div>
      </div>

      {/* Heatmap & Recommendation Section */}
      <div className="grid grid-cols-12 gap-8 mb-8">
        {/* Risk Heatmap */}
        <div className="col-span-12 lg:col-span-8">
          <div className="bg-surface-container-lowest rounded-xl shadow-sm p-6">
            <div className="flex items-center justify-between mb-8">
              <h3 className="text-sm font-bold uppercase tracking-tight text-on-surface">Vulnerable Clusters Heatmap</h3>
              <div className="flex gap-2">
                <span className="px-3 py-1 bg-surface-container-low rounded text-[0.6875rem] font-bold">Q-Day Estimation: 2029</span>
              </div>
            </div>
            <div className="relative aspect-[16/7] bg-surface-container-low rounded-lg overflow-hidden flex items-center justify-center p-4">
              <div className="absolute inset-0 grid grid-cols-8 grid-rows-4 gap-1 opacity-40">
                {/* Heatmap Nodes representation */}
                <div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-error/40 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div>
                <div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-error/60 rounded-sm"></div><div className="bg-error/80 rounded-sm"></div><div className="bg-error/30 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div>
                <div className="bg-tertiary/20 rounded-sm"></div><div className="bg-secondary-container/40 rounded-sm"></div><div className="bg-error/50 rounded-sm"></div><div className="bg-error/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div>
                <div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div><div className="bg-tertiary/20 rounded-sm"></div>
              </div>
              {/* Floating Data Tooltip over heatmap */}
              <div className="relative z-10 bg-white/90 backdrop-blur p-4 rounded-lg shadow-xl border border-outline-variant/20 max-w-[200px]">
                <p className="text-[0.625rem] font-bold text-on-surface-variant uppercase mb-1">Cluster US-EAST-1</p>
                <p className="text-xs font-bold text-error mb-2">RSA-2048 Detected (Legacy)</p>
                <div className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 rounded-full bg-error"></div>
                  <span className="text-[0.625rem] text-on-surface font-medium">Risk Score: 8.9/10</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Recommendations Panel */}
        <div className="col-span-12 lg:col-span-4 space-y-4">
          <div className="bg-surface-container-lowest rounded-xl shadow-sm p-6 border border-outline-variant/10">
            <h3 className="text-sm font-bold uppercase tracking-tight text-on-surface mb-6">Strategic Recommendations</h3>
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row gap-4">
                <div className="w-10 h-10 rounded bg-primary/5 flex items-center justify-center shrink-0">
                  <span className="material-symbols-outlined text-primary" data-icon="terminal">terminal</span>
                </div>
                <div>
                  <h4 className="text-xs font-bold text-on-surface">Upgrade TLS Protocols</h4>
                  <p className="text-[0.7rem] text-on-surface-variant mt-1 leading-relaxed">Mandate TLS 1.3 with hybrid PQC key exchange for all internal gateways.</p>
                  <button onClick={() => navigate('/scanner')} className="mt-2 text-primary text-[0.625rem] font-extrabold uppercase hover:underline w-full sm:w-auto">Apply Config</button>
                </div>
              </div>
              <div className="flex flex-col sm:flex-row gap-4">
                <div className="w-10 h-10 rounded bg-secondary-container/5 flex items-center justify-center shrink-0">
                  <span className="material-symbols-outlined text-secondary-container" data-icon="swap_horiz">swap_horiz</span>
                </div>
                <div>
                  <h4 className="text-xs font-bold text-on-surface">Replace RSA with CRYSTALS-Kyber</h4>
                  <p className="text-[0.7rem] text-on-surface-variant mt-1 leading-relaxed">Decommission RSA-2048 in critical load balancers. Replace with NIST Level 3 PQC.</p>
                  <button onClick={() => navigate('/asset-inventory')} className="mt-2 text-primary text-[0.625rem] font-extrabold uppercase hover:underline w-full sm:w-auto">View Assets</button>
                </div>
              </div>
              <div className="flex flex-col sm:flex-row gap-4">
                <div className="w-10 h-10 rounded bg-tertiary/5 flex items-center justify-center shrink-0">
                  <span className="material-symbols-outlined text-tertiary" data-icon="update">update</span>
                </div>
                <div>
                  <h4 className="text-xs font-bold text-on-surface">Update Crypto Libraries</h4>
                  <p className="text-[0.7rem] text-on-surface-variant mt-1 leading-relaxed">Version 4.2.0 of OpenSSL contains PQC patches. 48 nodes require updates.</p>
                  <button onClick={() => window.open(apiBase + '/api/reports/vulnerable-download?x_user_role=Super%20Admin', '_blank')} className="mt-2 text-primary text-[0.625rem] font-extrabold uppercase hover:underline w-full sm:w-auto">Deploy Update</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Asset Table */}
      <section className="bg-surface-container-lowest rounded-xl shadow-sm overflow-hidden border border-outline-variant/10">
        <div className="px-6 py-5 flex items-center justify-between">
          <h3 className="text-sm font-bold uppercase tracking-tight text-on-surface">Asset Posture Details</h3>
          <div className="flex gap-2">
            <button onClick={() => window.open(apiBase + '/api/assets', '_blank')} className="px-3 py-1.5 text-[0.7rem] font-bold border border-outline-variant/30 rounded hover:bg-surface-container-low transition-colors w-full sm:w-auto">Export CSV</button>
            <button onClick={() => navigate('/reports')} className="px-3 py-1.5 text-[0.7rem] font-bold bg-primary text-white rounded hover:bg-primary-container shadow-md shadow-primary/20 transition-colors w-full sm:w-auto">Detailed Audit</button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-surface-container-low">
              <tr>
                <th className="px-6 py-3 text-[0.6875rem] font-bold uppercase tracking-widest text-on-surface-variant">Asset Name</th>
                <th className="px-6 py-3 text-[0.6875rem] font-bold uppercase tracking-widest text-on-surface-variant">Type</th>
                <th className="px-6 py-3 text-[0.6875rem] font-bold uppercase tracking-widest text-on-surface-variant">Current Algorithm</th>
                <th className="px-6 py-3 text-[0.6875rem] font-bold uppercase tracking-widest text-on-surface-variant">PQC Support</th>
                <th className="px-6 py-3 text-[0.6875rem] font-bold uppercase tracking-widest text-on-surface-variant">Risk Level</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-outline-variant/10">
              <tr className="hover:bg-surface-container-low transition-colors">
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-on-surface-variant text-base" data-icon="storage">storage</span>
                    <span className="text-[0.8125rem] font-medium text-on-surface">db-primary-prod-01</span>
                  </div>
                </td>
                <td className="px-6 py-4 text-xs text-on-surface-variant">Database</td>
                <td className="px-6 py-4 text-xs font-mono">AES-256 / RSA-4096</td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
                    <span className="text-[0.7rem] font-bold text-tertiary">READY</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span className="px-2 py-0.5 rounded text-[0.625rem] font-bold bg-tertiary/10 text-tertiary uppercase">LOW</span>
                </td>
              </tr>
              <tr className="hover:bg-surface-container-low transition-colors">
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-on-surface-variant text-base" data-icon="dns">dns</span>
                    <span className="text-[0.8125rem] font-medium text-on-surface">api-gateway-us-east</span>
                  </div>
                </td>
                <td className="px-6 py-4 text-xs text-on-surface-variant">Gateway</td>
                <td className="px-6 py-4 text-xs font-mono">ECDH / RSA-2048</td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-secondary-container"></span>
                    <span className="text-[0.7rem] font-bold text-secondary-container">PENDING</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span className="px-2 py-0.5 rounded text-[0.625rem] font-bold bg-secondary-container/10 text-secondary uppercase">MEDIUM</span>
                </td>
              </tr>
              <tr className="hover:bg-surface-container-low transition-colors">
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-on-surface-variant text-base" data-icon="vpn_key">vpn_key</span>
                    <span className="text-[0.8125rem] font-medium text-on-surface">legacy-auth-service</span>
                  </div>
                </td>
                <td className="px-6 py-4 text-xs text-on-surface-variant">Microservice</td>
                <td className="px-6 py-4 text-xs font-mono">SHA-1 / RSA-1024</td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-error"></span>
                    <span className="text-[0.7rem] font-bold text-error">INCOMPATIBLE</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span className="px-2 py-0.5 rounded text-[0.625rem] font-bold bg-error/10 text-error uppercase">CRITICAL</span>
                </td>
              </tr>
              <tr className="hover:bg-surface-container-low transition-colors">
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-on-surface-variant text-base" data-icon="cloud_queue">cloud_queue</span>
                    <span className="text-[0.8125rem] font-medium text-on-surface">cloud-storage-bucket-zeta</span>
                  </div>
                </td>
                <td className="px-6 py-4 text-xs text-on-surface-variant">Object Store</td>
                <td className="px-6 py-4 text-xs font-mono">Kyber-1024 (PQC)</td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-tertiary" style={{ boxShadow: '0 0 8px #006645' }}></span>
                    <span className="text-[0.7rem] font-bold text-tertiary">ACTIVE</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span className="px-2 py-0.5 rounded text-[0.625rem] font-bold bg-tertiary/10 text-tertiary uppercase">QUANTUM-SAFE</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div className="px-6 py-4 bg-surface-container-low/30 border-t border-outline-variant/10 text-center">
          <button onClick={() => navigate('/asset-inventory')} className="text-[0.7rem] font-bold text-primary hover:text-primary-container transition-colors w-full sm:w-auto">View All 1,402 Assets</button>
        </div>
      </section>
    </main>
  );
};

export default PqcPosture;
