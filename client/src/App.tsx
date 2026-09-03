import React, { useState, useEffect } from 'react';
import { HashRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { ShieldAlert, Lock, LogIn, Timer } from 'lucide-react';

// ── Auth Guard Popup ──────────────────────────────────────────────────────────
const AuthGuardPopup = () => {
  const navigate = useNavigate();
  const [countdown, setCountdown] = useState(5);

  useEffect(() => {
    const timer = setInterval(() => {
      setCountdown(prev => {
        if (prev <= 1) { clearInterval(timer); navigate('/login'); return 0; }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [navigate]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#080a0c]/90 backdrop-blur-xl">
      {/* Animated background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-red-500/5 rounded-full blur-3xl animate-pulse" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-brand/5 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }} />
      </div>

      <div className="relative bg-[#0f1418]/90 backdrop-blur-2xl border border-[#1e262e] rounded-2xl p-10 max-w-md w-full mx-4 shadow-2xl shadow-black/50 text-center">
        {/* Animated Lock Icon */}
        <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-red-600/20 to-red-600/20 border border-red-500/30 flex items-center justify-center mx-auto mb-6 animate-bounce" style={{ animationDuration: '2s' }}>
          <Lock size={36} className="text-red-400" />
        </div>

        <h2 className="text-2xl font-black text-white mb-2 tracking-tight">Authentication Required</h2>
        <p className="text-[#9ca3af] text-sm mb-6 leading-relaxed">
          You cannot access this page without logging in. Please sign in to your RedVapt account to continue.
        </p>

        {/* Countdown */}
        <div className="flex items-center justify-center gap-2 mb-6 text-[#6b7280] text-xs">
          <Timer size={14} className="text-brand" />
          <span>Auto-redirecting in <span className="text-brand font-black text-sm">{countdown}</span> seconds</span>
        </div>

        {/* Login Button */}
        <button
          onClick={() => navigate('/login')}
          className="w-full flex items-center justify-center gap-2 py-3.5 bg-gradient-to-r from-brand to-red-800 hover:from-red-600 hover:to-red-900 text-white rounded-xl font-bold text-sm transition-all shadow-lg shadow-brand/25 hover:shadow-brand/30 hover:-translate-y-0.5"
        >
          <LogIn size={18} />
          Go to Login
        </button>

        <p className="text-[#64748b] text-[10px] mt-4 uppercase font-bold tracking-wider">
          <ShieldAlert size={10} className="inline mr-1" />
          Secure Access Only
        </p>
      </div>
    </div>
  );
};

// ── Protected Route with Popup ────────────────────────────────────────────────
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem('accessToken');
  const workspaceId = localStorage.getItem('workspaceId');
  const isValid = token && token !== 'undefined' && token !== 'null' && workspaceId && workspaceId !== 'undefined' && workspaceId !== 'null';
  
  useEffect(() => {
    if (!isValid) {
      console.warn('ProtectedRoute: Invalid Auth State', { token: !!token, workspaceId });
    }
  }, [isValid, token, workspaceId]);

  return isValid ? <>{children}</> : <AuthGuardPopup />;
};

import PublicLayout from './components/layout/PublicLayout';
import WorkspaceLayout from './components/layout/WorkspaceLayout';
import Dashboard from './pages/Dashboard';
import WorkspaceDashboard from './pages/WorkspaceDashboard';
import AIScanner from './pages/AIScanner';
import Assets from './pages/Assets';
import Findings from './pages/Findings';
import AttackSurface from './pages/AttackSurface';
import About from './pages/About';
import Services from './pages/Services';
import Tools from './pages/Tools';
import BookDemo from './pages/BookDemo';
import Vulnerabilities from './pages/Vulnerabilities';
import Reports from './pages/Reports';
import Login from './pages/Login';
import Privacy from './pages/Privacy';
import Terms from './pages/Terms';
import Settings from './pages/Settings';

const App: React.FC = () => {
  return (
    <Router>
      <Routes>
        {/* Public Routes with Navbar and Footer */}
        <Route path="/" element={<PublicLayout><Dashboard /></PublicLayout>} />
        <Route path="/about" element={<PublicLayout><About /></PublicLayout>} />
        <Route path="/services" element={<PublicLayout><Services /></PublicLayout>} />
        <Route path="/tools" element={<PublicLayout><Tools /></PublicLayout>} />
        <Route path="/book-demo" element={<PublicLayout><BookDemo /></PublicLayout>} />
        <Route path="/ai-scanner" element={<ProtectedRoute><PublicLayout><AIScanner /></PublicLayout></ProtectedRoute>} />
        <Route path="/vulnerabilities" element={<PublicLayout><Vulnerabilities /></PublicLayout>} />
        <Route path="/reports" element={<ProtectedRoute><PublicLayout><Reports /></PublicLayout></ProtectedRoute>} />
        <Route path="/login" element={<PublicLayout><Login /></PublicLayout>} />
        <Route path="/privacy" element={<PublicLayout><Privacy /></PublicLayout>} />
        <Route path="/terms" element={<PublicLayout><Terms /></PublicLayout>} />

        {/* Protected Workspace Routes (wrapped in WorkspaceLayout with Sidebar) */}
        <Route
          path="/workspace/*"
          element={
            <ProtectedRoute>
              <WorkspaceLayout>
                <Routes>
                  <Route path="dashboard" element={<WorkspaceDashboard />} />
                  <Route path="assets" element={<Assets />} />
                  <Route path="scans" element={<AIScanner />} />
                  <Route path="findings" element={<Findings />} />
                  <Route path="attack-surface" element={<AttackSurface />} />
                  <Route path="reports" element={<Reports />} />
                  <Route path="settings" element={<Settings />} />
                  <Route path="*" element={<Navigate to="dashboard" replace />} />
                </Routes>
              </WorkspaceLayout>
            </ProtectedRoute>
          }
        />

        {/* Fallback */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
};

export default App;
