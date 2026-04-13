import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const CyberRating = () => {
  const navigate = useNavigate();
  const [vulnerableAssets, setVulnerableAssets] = useState<any[]>([]);

  useEffect(() => {
    fetch((import.meta.env.VITE_API_URL || 'http://localhost:8010') + '/api/vulnerable-assets')
      .then(res => res.json())
      .then(data => setVulnerableAssets(data))
      .catch(err => console.error("Failed to fetch vulnerable assets:", err));
  }, []);

  return (
    <main className="md:ml-64 pt-24 pb-12 px-10 min-h-screen">
      {/* Executive Overview Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 md:gap-0 mb-10">
        <div>
          <h2 className="text-[1.75rem] font-bold text-on-surface tracking-tight leading-none mb-2">Cyber Rating</h2>
          <p className="text-on-surface-variant text-sm max-w-xl">Comprehensive cryptographic health assessment based on post-quantum resilience benchmarks and NIST entropy standards.</p>
        </div>
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="px-4 py-2 bg-tertiary/10 border border-tertiary/20 rounded-lg flex items-center gap-2">
            <span className="material-symbols-outlined text-tertiary text-lg" style={{ fontVariationSettings: "'FILL' 1" }}>verified</span>
            <span className="text-tertiary font-bold text-sm uppercase tracking-wider">Elite-PQC</span>
          </div>
          <button 
            onClick={() => window.open((import.meta.env.VITE_API_URL || 'http://localhost:8010') + '/api/reports/download', '_blank')}
            className="bg-surface-container-highest text-on-surface px-6 py-2 rounded-lg text-sm font-semibold hover:bg-surface-variant transition-colors shadow-sm w-full sm:w-auto"
          >
            Export Executive Summary
          </button>
        </div>
      </div>

      {/* Vulnerable Assets Section (Dynamic) */}
      {vulnerableAssets.length > 0 && (
        <div className="mb-8 bg-error/10 border border-error/30 rounded-xl overflow-hidden shadow-sm relative group">
          <div className="p-6 border-b border-error/20 flex justify-between items-center bg-error/5 relative z-10">
             <div className="flex items-center gap-3">
               <span className="material-symbols-outlined text-error animate-pulse">warning</span>
               <h3 className="text-sm font-bold text-error uppercase tracking-wider">Critical Vulnerabilities Detected ({vulnerableAssets.length})</h3>
             </div>
          </div>
          <div className="overflow-x-auto relative z-10 custom-scrollbar w-full">
            <table className="w-full text-left">
              <thead>
                <tr className="bg-error/5">
                  <th className="px-6 py-3 text-[10px] text-error font-bold uppercase tracking-widest border-b border-error/20">Target / Asset</th>
                  <th className="px-6 py-3 text-[10px] text-error font-bold uppercase tracking-widest border-b border-error/20">Algorithm</th>
                  <th className="px-6 py-3 text-[10px] text-error font-bold uppercase tracking-widest border-b border-error/20">TLS Version</th>
                  <th className="px-6 py-3 text-[10px] text-error font-bold uppercase tracking-widest border-b border-error/20 text-right">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-error/10">
                {vulnerableAssets.map((asset, i) => (
                   <tr key={i} className="hover:bg-error/10 transition-colors">
                     <td className="px-6 py-4">
                       <p className="text-xs font-bold text-on-surface">{asset.name}</p>
                       <p className="text-[10px] text-on-surface-variant font-mono mt-0.5">{asset.ip_address || '---'}</p>
                     </td>
                     <td className="px-6 py-4">
                       <span className="text-xs px-2 py-1 bg-surface-container-lowest border border-error/20 rounded text-error font-mono">{asset.scan_result?.algorithm || 'Unknown'}</span>
                     </td>
                     <td className="px-6 py-4">
                       <span className="text-[11px] font-medium text-error">{asset.scan_result?.tls_version || 'Unknown'}</span>
                     </td>
                     <td className="px-6 py-4 text-right">
                       <span className="text-[10px] font-bold py-1 px-2 bg-error text-white rounded">
                         {asset.risk?.risk_level || 'High'}
                       </span>
                     </td>
                   </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Bento Grid Layout */}
      <div className="grid grid-cols-12 gap-8 mb-8">
        {/* Main Score Card (Visual Heatmap) */}
        <div className="col-span-12 lg:col-span-8 bg-surface-container-lowest rounded-xl p-8 shadow-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-1/3 h-full opacity-5 pointer-events-none">
            <svg className="w-full h-full text-primary fill-current" viewBox="0 0 100 100">
              <path d="M0,50 Q25,25 50,50 T100,50" fill="none" stroke="currentColor" strokeWidth="0.5"></path>
            </svg>
          </div>
          <div className="flex flex-col md:flex-row gap-12 items-center">
            <div className="relative w-64 h-64 flex items-center justify-center">
              {/* Custom Entropy Gauge Mockup */}
              <svg className="w-full h-full -rotate-90">
                <circle className="opacity-50" cx="128" cy="128" fill="none" r="110" stroke="#eceef0" strokeWidth="16"></circle>
                <circle cx="128" cy="128" fill="none" r="110" stroke="url(#score-grad)" strokeDasharray="690" strokeDashoffset="172" strokeLinecap="round" strokeWidth="16"></circle>
                <defs>
                  <linearGradient id="score-grad" x1="0%" x2="100%" y1="0%" y2="0%">
                    <stop offset="0%" stopColor="#ba1a1a"></stop>
                    <stop offset="50%" stopColor="#2170e4"></stop>
                    <stop offset="100%" stopColor="#006645"></stop>
                  </linearGradient>
                </defs>
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-5xl font-extrabold text-on-surface">755</span>
                <span className="text-[11px] text-on-surface-variant uppercase font-bold tracking-widest mt-1">Score / 1000</span>
              </div>
            </div>
            
            <div className="flex-1 w-full">
              <h3 className="text-sm font-bold text-on-surface mb-6 uppercase tracking-wider">Risk Distribution Heatmap</h3>
              <div className="grid grid-cols-5 gap-2 h-48">
                {/* Heatmap Rectangles */}
                <div className="bg-tertiary/20 rounded-md border-b-4 border-tertiary"></div>
                <div className="bg-tertiary/40 rounded-md border-b-4 border-tertiary"></div>
                <div className="bg-secondary-container/30 rounded-md border-b-4 border-secondary-container"></div>
                <div className="bg-secondary-container/10 rounded-md border-b-2 border-secondary-container/30"></div>
                <div className="bg-error/10 rounded-md border-b-2 border-error/20"></div>
                {/* Legend */}
                <div className="col-span-5 flex justify-between mt-4">
                  <span className="text-[10px] font-bold text-tertiary uppercase tracking-tight">Quantum-Safe</span>
                  <span className="text-[10px] font-bold text-error uppercase tracking-tight">Critical Risk</span>
                </div>
              </div>
              <div className="mt-8 flex gap-8">
                <div>
                  <p className="text-[11px] text-on-surface-variant mb-1 uppercase tracking-tighter">Analyzed Assets</p>
                  <p className="text-2xl font-bold text-primary">14,208</p>
                </div>
                <div className="h-10 w-px bg-outline-variant/30"></div>
                <div>
                  <p className="text-[11px] text-on-surface-variant mb-1 uppercase tracking-tighter">Avg Entropy</p>
                  <p className="text-2xl font-bold text-tertiary">0.998</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Global Comparison Sidebar */}
        <div className="col-span-12 lg:col-span-4 flex flex-col gap-6">
          <div className="bg-surface-container-low rounded-xl p-6 flex-1 border border-outline-variant/10">
            <h3 className="text-[11px] font-bold text-on-surface-variant mb-6 uppercase tracking-widest">Industry Benchmark</h3>
            <div className="space-y-6">
              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-sm font-medium">Your Org</span>
                  <span className="text-sm font-bold">755</span>
                </div>
                <div className="h-2 w-full bg-surface-container-highest rounded-full overflow-hidden">
                  <div className="h-full bg-primary" style={{ width: '75%' }}></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between items-center text-on-surface-variant mb-1.5">
                  <span className="text-sm font-medium">Finance Sector Avg</span>
                  <span className="text-sm font-bold">542</span>
                </div>
                <div className="h-2 w-full bg-surface-container-highest rounded-full overflow-hidden">
                  <div className="h-full bg-outline-variant" style={{ width: '54%' }}></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between items-center text-on-surface-variant mb-1.5">
                  <span className="text-sm font-medium">Global Fortune 500</span>
                  <span className="text-sm font-bold">610</span>
                </div>
                <div className="h-2 w-full bg-surface-container-highest rounded-full overflow-hidden">
                  <div className="h-full bg-outline-variant" style={{ width: '61%' }}></div>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-primary text-white rounded-xl p-6 shadow-lg shadow-primary/20 bg-gradient-to-br from-primary to-primary-container">
            <div className="flex justify-between items-start mb-4">
              <span className="material-symbols-outlined text-3xl opacity-80">psychology</span>
              <span className="text-[10px] bg-white/20 px-2 py-0.5 rounded uppercase font-bold tracking-widest">AI Insight</span>
            </div>
            <p className="text-sm font-medium leading-relaxed">Transitioning 4 legacy TLS 1.2 endpoints to Dilithium-ready protocols would increase your score by <span className="font-bold underline">+85 points</span>.</p>
          </div>
        </div>
      </div>

      {/* Asset Rating Table */}
      <div className="bg-surface-container-lowest rounded-xl shadow-sm overflow-hidden border border-outline-variant/10">
        <div className="p-6 border-b border-surface-container-low flex justify-between items-center flex-col sm:flex-row gap-4 items-start sm:items-center">
          <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider">Asset Vulnerability Matrix</h3>
          <button onClick={() => navigate('/asset-inventory')} className="flex items-center gap-2 cursor-pointer hover:text-primary transition-colors">
            <span className="material-symbols-outlined text-slate-400">filter_list</span>
            <span className="text-xs font-bold text-on-surface-variant uppercase tracking-tighter">Filter by Score</span>
          </button>
        </div>
        
        <div className="overflow-x-auto custom-scrollbar w-full">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-surface-container-low/50">
                <th className="px-6 py-4 text-[11px] text-on-surface-variant font-bold uppercase tracking-widest">Target URL / Asset</th>
                <th className="px-6 py-4 text-[11px] text-on-surface-variant font-bold uppercase tracking-widest">Algorithm</th>
                <th className="px-6 py-4 text-[11px] text-on-surface-variant font-bold uppercase tracking-widest">Status</th>
                <th className="px-6 py-4 text-[11px] text-on-surface-variant font-bold uppercase tracking-widest">PQC Score</th>
                <th className="px-6 py-4 text-[11px] text-on-surface-variant font-bold uppercase tracking-widest text-right">Trend</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-container-low">
              <tr className="hover:bg-surface-container-low transition-colors group">
                <td className="px-6 py-4">
                  <p className="text-sm font-semibold text-on-surface">api.nexus-core.internal</p>
                  <p className="text-[10px] text-on-surface-variant font-mono">10.0.4.122</p>
                </td>
                <td className="px-6 py-4">
                  <span className="text-xs px-2 py-1 bg-surface-container-high rounded text-on-surface font-mono">Kyber-768</span>
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-tertiary"></div>
                    <span className="text-xs font-bold uppercase tracking-tight text-tertiary">Elite-PQC</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span className="text-sm font-bold text-on-surface">942</span>
                </td>
                <td className="px-6 py-4 text-right">
                  <span className="material-symbols-outlined text-tertiary text-lg">trending_up</span>
                </td>
              </tr>
              <tr className="hover:bg-surface-container-low transition-colors group">
                <td className="px-6 py-4">
                  <p className="text-sm font-semibold text-on-surface">db-cluster-prod-01</p>
                  <p className="text-[10px] text-on-surface-variant font-mono">10.0.12.44</p>
                </td>
                <td className="px-6 py-4">
                  <span className="text-xs px-2 py-1 bg-surface-container-high rounded text-on-surface font-mono">AES-256-GCM</span>
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-secondary-container"></div>
                    <span className="text-xs font-bold uppercase tracking-tight text-secondary-container">Standard</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span className="text-sm font-bold text-on-surface">618</span>
                </td>
                <td className="px-6 py-4 text-right">
                  <span className="material-symbols-outlined text-slate-400 text-lg">trending_flat</span>
                </td>
              </tr>
              <tr className="hover:bg-surface-container-low transition-colors group">
                <td className="px-6 py-4">
                  <p className="text-sm font-semibold text-on-surface">legacy-gateway-auth</p>
                  <p className="text-[10px] text-on-surface-variant font-mono">172.16.8.9</p>
                </td>
                <td className="px-6 py-4">
                  <span className="text-xs px-2 py-1 bg-surface-container-high rounded text-on-surface font-mono">RSA-2048</span>
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-error"></div>
                    <span className="text-xs font-bold uppercase tracking-tight text-error">Legacy</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span className="text-sm font-bold text-on-surface">144</span>
                </td>
                <td className="px-6 py-4 text-right">
                  <span className="material-symbols-outlined text-error text-lg">trending_down</span>
                </td>
              </tr>
              <tr className="hover:bg-surface-container-low transition-colors group">
                <td className="px-6 py-4">
                  <p className="text-sm font-semibold text-on-surface">cdn-edge-global-02</p>
                  <p className="text-[10px] text-on-surface-variant font-mono">92.44.121.2</p>
                </td>
                <td className="px-6 py-4">
                  <span className="text-xs px-2 py-1 bg-surface-container-high rounded text-on-surface font-mono">Dilithium-3</span>
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-tertiary"></div>
                    <span className="text-xs font-bold uppercase tracking-tight text-tertiary">Elite-PQC</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span className="text-sm font-bold text-on-surface">885</span>
                </td>
                <td className="px-6 py-4 text-right">
                  <span className="material-symbols-outlined text-tertiary text-lg">trending_up</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div className="p-4 bg-surface-container-low/30 border-t border-surface-container-low flex justify-center">
          <button onClick={() => navigate('/asset-inventory')} className="text-primary text-xs font-bold uppercase tracking-widest hover:underline transition-colors w-full sm:w-auto">View All 412 Assets</button>
        </div>
      </div>
    </main>
  );
};

export default CyberRating;

