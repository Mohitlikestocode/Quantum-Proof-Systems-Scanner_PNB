import { useState } from 'react';

type AuthSession = {
  username: string;
  name: string;
  role: 'Super Admin' | 'Admin' | 'User';
};

export default function Login({ onLogin }: { onLogin: (session: AuthSession) => void }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<'Super Admin' | 'Admin' | 'User'>('User');
  const [mode, setMode] = useState<'direct' | 'otp'>('direct');
  const [step, setStep] = useState<'login' | 'otp'>('login');
  const [otp, setOtp] = useState(['', '', '', '', '', '']);

  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const getPrototypeSessionByRole = (selectedRole: 'Super Admin' | 'Admin' | 'User'): AuthSession => {
    if (selectedRole === 'Super Admin') {
      return { username: 'admin@quantumshield.local', name: 'System Administrator', role: 'Super Admin' };
    }
    if (selectedRole === 'Admin') {
      return { username: 'j.doe@quantumshield.local', name: 'John Doe', role: 'Admin' };
    }
    return { username: 'guest@quantumshield.local', name: 'Guest Viewer', role: 'User' };
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg('');
    try {
      if (mode === 'direct') {
        // Prototype mode: direct login should work on static/Vercel deployments even without backend API.
        onLogin(getPrototypeSessionByRole(role));
        setLoading(false);
        return;
      }

      const endpoint = '/api/auth/send-otp';
      const res = await fetch((import.meta.env.VITE_API_URL || 'http://localhost:8010') + endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, role })
      });
      if (res.ok) {
        setStep('otp');
      } else {
        const payload = await res.json().catch(() => ({}));
        setErrorMsg(payload.detail || 'Failed to send OTP. Is the backend running?');
      }
    } catch (err) {
      setErrorMsg('Network error connecting to backend.');
    }
    setLoading(false);
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    const code = otp.join('');
    if (code.length === 6) {
      setLoading(true);
      setErrorMsg('');
      try {
        const res = await fetch((import.meta.env.VITE_API_URL || 'http://localhost:8010') + '/api/auth/verify-otp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, otp: code })
        });
        if (res.ok) {
          const payload = await res.json();
          const session: AuthSession = {
            username: payload.username || email,
            name: payload.name || email,
            role: payload.role || role
          };
          onLogin(session);
        } else {
          const payload = await res.json().catch(() => ({}));
          setErrorMsg(payload.detail || 'Invalid or expired OTP.');
        }
      } catch (err) {
        setErrorMsg('Network error.');
      }
      setLoading(false);
    }
  };

  const handleOtpChange = (index: number, value: string) => {
    if (!/^\d*$/.test(value)) return;
    const newOtp = [...otp];
    newOtp[index] = value;
    setOtp(newOtp);
    // Auto-focus next input
    if (value && index < 5) {
      const nextInput = document.getElementById(`otp-${index + 1}`);
      nextInput?.focus();
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4 sm:p-6 md:p-8">
      <div className="max-w-md w-full bg-surface-container-lowest p-8 rounded-2xl shadow-lg border border-outline-variant/10">
        <div className="flex justify-center mb-8">
          <div className="w-16 h-16 bg-primary/10 rounded-2xl flex items-center justify-center shadow-inner">
            <span className="material-symbols-outlined text-[32px] text-primary" data-icon="shield_lock">shield_lock</span>
          </div>
        </div>
        <h2 className="text-2xl font-extrabold text-on-surface text-center mb-2">Quantum Shield</h2>
        <p className="text-sm font-medium text-on-surface-variant text-center mb-8">
          {step === 'login' ? (mode === 'otp' ? 'Two-Factor Authentication' : 'Direct Secure Gateway Login') : 'Two-Factor Authentication'}
        </p>

        {step === 'login' ? (
          <form onSubmit={handleLogin} className="space-y-5">
            <div className="grid grid-cols-2 gap-2 p-1 bg-surface-container-highest rounded-xl border border-outline-variant/20">
              <button
                type="button"
                onClick={() => setMode('direct')}
                className={`py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors ${mode === 'direct' ? 'bg-primary text-white' : 'text-on-surface-variant hover:text-on-surface'}`}
              >
                Direct Login
              </button>
              <button
                type="button"
                onClick={() => setMode('otp')}
                className={`py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors ${mode === 'otp' ? 'bg-primary text-white' : 'text-on-surface-variant hover:text-on-surface'}`}
              >
                OTP Login
              </button>
            </div>
            <div>
              <label className="block text-xs font-bold text-on-surface-variant uppercase tracking-wider mb-2">Role</label>
              <select
                required
                className="w-full px-4 py-3 bg-surface-container-highest rounded-xl border border-outline-variant/30 focus:border-primary focus:ring-1 focus:ring-primary transition-all text-sm font-medium text-on-surface"
                value={role}
                onChange={(e) => setRole(e.target.value as 'Super Admin' | 'Admin' | 'User')}
              >
                <option value="Super Admin">Super Admin</option>
                <option value="Admin">Admin</option>
                <option value="User">User</option>
              </select>
            </div>
            {mode === 'otp' && (
              <>
                <div>
                  <label className="block text-xs font-bold text-on-surface-variant uppercase tracking-wider mb-2">Work Email</label>
                  <input
                    type="email"
                    required
                    className="w-full px-4 py-3 bg-surface-container-highest rounded-xl border border-outline-variant/30 focus:border-primary focus:ring-1 focus:ring-primary transition-all text-sm font-medium text-on-surface"
                    placeholder="admin@quantumshield.local"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold text-on-surface-variant uppercase tracking-wider mb-2">Password</label>
                  <input
                    type="password"
                    required
                    className="w-full px-4 py-3 bg-surface-container-highest rounded-xl border border-outline-variant/30 focus:border-primary focus:ring-1 focus:ring-primary transition-all text-sm font-medium text-on-surface"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </div>
              </>
            )}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-primary text-white rounded-xl font-bold text-sm shadow-md hover:bg-primary/90 transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading ? (mode === 'otp' ? 'Sending OTP...' : 'Signing In...') : (mode === 'otp' ? 'Sign In with OTP' : 'Direct Login')} <span className="material-symbols-outlined text-[18px]">lock_open</span>
            </button>
            <div className="rounded-xl bg-surface-container-highest p-3 text-[11px] text-on-surface-variant leading-relaxed border border-outline-variant/20">
              Demo credentials: super admin <b>admin@quantumshield.local / Admin@123</b>, admin <b>j.doe@quantumshield.local / Admin@123</b>, user <b>guest@quantumshield.local / User@123</b>.
            </div>
            {errorMsg && <p className="text-error text-xs font-bold text-center mt-2">{errorMsg}</p>}
          </form>
        ) : (
          <form onSubmit={handleVerify} className="space-y-6">
            <p className="text-xs font-bold text-on-surface-variant text-center mb-4">
              Enter the 6-digit code sent to {email}
            </p>
            <div className="flex justify-between gap-2">
              {otp.map((digit, idx) => (
                <input
                  key={idx}
                  id={`otp-${idx}`}
                  type="text"
                  maxLength={1}
                  required
                  className="w-12 h-14 bg-surface-container-highest rounded-xl border border-outline-variant/30 focus:border-primary focus:ring-1 focus:ring-primary transition-all text-xl font-bold text-center text-on-surface"
                  value={digit}
                  onChange={(e) => handleOtpChange(idx, e.target.value)}
                />
              ))}
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-primary text-white rounded-xl font-bold text-sm shadow-md hover:bg-primary/90 transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Verify OTP'} <span className="material-symbols-outlined text-[18px]">verified_user</span>
            </button>
            {errorMsg && <p className="text-error text-xs font-bold text-center mt-2">{errorMsg}</p>}
            <button
              type="button"
              onClick={() => { setMode(mode === 'otp' ? 'direct' : 'otp'); setStep('login'); setErrorMsg(''); setOtp(['','','','','','']); }}
              className="w-full py-2 text-primary font-bold text-xs uppercase hover:underline mt-2"
            >
              Switch to {mode === 'otp' ? 'Direct Login' : 'OTP Login'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
