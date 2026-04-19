import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import AssetDiscovery from './components/AssetDiscovery';
import AssetInventory from './components/AssetInventory';
import Scanner from './components/Scanner';
import AIAssistant from './components/AIAssistant';
import Cbom from './components/Cbom';
import PqcPosture from './components/PqcPosture';
import CyberRating from './components/CyberRating';
import Reports from './components/Reports';
import Login from './components/Login';
import { useState } from 'react';

type AuthSession = {
  username: string;
  name: string;
  role: 'Super Admin' | 'Admin' | 'User';
};

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [session, setSession] = useState<AuthSession | null>(() => {
    const raw = localStorage.getItem('authSession');
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  });

  const handleLogin = (authSession: AuthSession) => {
    localStorage.setItem('authSession', JSON.stringify(authSession));
    localStorage.setItem('userRole', authSession.role);
    setSession(authSession);
  };

  const handleLogout = () => {
    localStorage.removeItem('authSession');
    localStorage.removeItem('userRole');
    setSession(null);
  };

  if (!session) {
    return <Login onLogin={handleLogin} />;
  }
  
  return (
    <Router>
      <div className="min-h-screen">
        <Sidebar isOpen={sidebarOpen} setIsOpen={setSidebarOpen} />
        <Header setSidebarOpen={setSidebarOpen} onSwitchAccount={handleLogout} />
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/asset-discovery" element={<AssetDiscovery />} />
          <Route path="/asset-inventory" element={<AssetInventory />} />
          <Route path="/scanner" element={<Scanner />} />
          <Route path="/cbom" element={<Cbom />} />
          <Route path="/pqc-posture" element={<PqcPosture />} />
          <Route path="/cyber-rating" element={<CyberRating />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/ai-assistant" element={<AIAssistant />} />
          <Route path="*" element={<Dashboard />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;

