import { NavLink } from 'react-router-dom';
import { useNavigate } from 'react-router-dom';

interface SidebarProps {
  isOpen: boolean;
  setIsOpen: (val: boolean) => void;
}

const Sidebar = ({ isOpen, setIsOpen }: SidebarProps) => {
  const navigate = useNavigate();
  const getNavLinkClass = ({ isActive }: { isActive: boolean }) => {
    return isActive
      ? "flex items-center gap-3 px-3 py-2.5 text-blue-700 font-semibold border-r-4 border-blue-700 bg-blue-50/50 transition-colors duration-200"
      : "flex items-center gap-3 px-3 py-2.5 text-slate-600 hover:text-slate-900 hover:bg-slate-200/50 transition-colors duration-200 scale-95 active:scale-100 cursor-pointer rounded";
  };

  return (
    <>
      {/* Mobile Overlay */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-slate-900/50 z-40 md:hidden"
          onClick={() => setIsOpen(false)}
        />
      )}
      
      <aside className={`h-screen w-64 fixed left-0 top-0 border-r-0 bg-slate-50 flex flex-col py-6 px-4 z-50 overflow-y-auto no-scrollbar transition-transform duration-300 ${isOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"}`}>
        <div className="mb-10 px-2 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-gradient-to-br from-primary to-primary-container flex items-center justify-center text-white">
              <span className="material-symbols-outlined text-[20px]" data-icon="security" style={{ fontVariationSettings: "'FILL' 1" }}>security</span>
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight text-slate-900 leading-none">Quantum-Proof</h1>
              <p className="text-[10px] text-slate-500 font-bold tracking-widest uppercase mt-1">Systems Scanner</p>
            </div>
          </div>
          <button onClick={() => setIsOpen(false)} className="md:hidden text-slate-500 hover:text-slate-800">
            <span className="material-symbols-outlined">close</span>
          </button>
        </div>

      <nav className="flex-1 space-y-1">
        <NavLink to="/dashboard" className={getNavLinkClass}>
          <span className="material-symbols-outlined text-[20px]" data-icon="dashboard">dashboard</span>
          <span className="font-sans text-[0.875rem] font-medium tracking-tight">Dashboard</span>
        </NavLink>
        
        <NavLink to="/asset-inventory" className={getNavLinkClass}>
          <span className="material-symbols-outlined text-[20px]" data-icon="inventory_2">inventory_2</span>
          <span className="font-sans text-[0.875rem] font-medium tracking-tight">Asset Inventory</span>
        </NavLink>
        
        <NavLink to="/asset-discovery" className={getNavLinkClass}>
          <span className="material-symbols-outlined text-[20px]" data-icon="search_check">search_check</span>
          <span className="font-sans text-[0.875rem] font-medium tracking-tight">Asset Discovery</span>
        </NavLink>
        
        <NavLink to="/scanner" className={getNavLinkClass}>
          <span className="material-symbols-outlined text-[20px]" data-icon="biotech">biotech</span>
          <span className="font-sans text-[0.875rem] font-medium tracking-tight">Scanner</span>
        </NavLink>
        
        <NavLink to="/cbom" className={getNavLinkClass}>
          <span className="material-symbols-outlined text-[20px]" data-icon="account_tree">account_tree</span>
          <span className="font-sans text-[0.875rem] font-medium tracking-tight">CBOM</span>
        </NavLink>
        
        <NavLink to="/pqc-posture" className={getNavLinkClass}>
          <span className="material-symbols-outlined text-[20px]" data-icon="security">security</span>
          <span className="font-sans text-[0.875rem] font-medium tracking-tight">PQC Posture</span>
        </NavLink>
        
        <NavLink to="/cyber-rating" className={getNavLinkClass}>
          <span className="material-symbols-outlined text-[20px]" data-icon="speed">speed</span>
          <span className="font-sans text-[0.875rem] font-medium tracking-tight">Cyber Rating</span>
        </NavLink>
        
        <NavLink to="/reports" className={getNavLinkClass}>
          <span className="material-symbols-outlined text-[20px]" data-icon="assessment">assessment</span>
          <span className="font-sans text-[0.875rem] font-medium tracking-tight">Reports</span>
        </NavLink>
        
        <NavLink to="/ai-assistant" className={getNavLinkClass}>
          <span className="material-symbols-outlined text-[20px]" data-icon="smart_toy">smart_toy</span>
          <span className="font-sans text-[0.875rem] font-medium tracking-tight">AI Assistant</span>
        </NavLink>
      </nav>

      <div className="mt-auto space-y-1">
        <button
          onClick={() => {
            navigate('/scanner');
            setIsOpen(false);
          }}
          className="w-full bg-gradient-to-br from-primary to-primary-container text-white py-2.5 rounded-lg text-sm font-semibold mb-6 shadow-md shadow-primary/20 hover:scale-105 active:scale-95 transition-transform flex items-center justify-center gap-2"
        >
          Start Scan
        </button>
        <button
          onClick={() => navigate('/reports')}
          className="w-full flex items-center gap-3 px-3 py-2 text-slate-600 hover:text-slate-900 hover:bg-slate-200/50 transition-colors duration-200 rounded cursor-pointer"
        >
          <span className="material-symbols-outlined text-[20px]" data-icon="settings">settings</span>
          <span className="font-sans text-[0.875rem] font-medium tracking-tight">Settings</span>
        </button>
        <button
          onClick={() => window.open('mailto:support@quantumshield.local?subject=Quantum%20Shield%20Support%20Request')}
          className="w-full flex items-center gap-3 px-3 py-2 text-slate-600 hover:text-slate-900 hover:bg-slate-200/50 transition-colors duration-200 rounded cursor-pointer"
        >
          <span className="material-symbols-outlined text-[20px]" data-icon="help">help</span>
          <span className="font-sans text-[0.875rem] font-medium tracking-tight">Support</span>
        </button>
      </div>
    </aside>
    </>
  );
};

export default Sidebar;
