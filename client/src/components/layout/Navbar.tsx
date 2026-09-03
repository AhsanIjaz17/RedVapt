import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, Info, Terminal, AlertCircle, FileText, Zap, Box, Lock, X } from 'lucide-react';
import logo from '../../assets/logo.png';

const Navbar: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [attemptedRoute, setAttemptedRoute] = useState('');

  const navItems = [
    { name: 'Dashboard', path: '/', icon: <LayoutDashboard size={18} /> },
    { name: 'About', path: '/about', icon: <Info size={18} /> },
    { name: 'Services', path: '/services', icon: <Box size={18} /> },
    { name: 'AI Scanner', path: '/ai-scanner', icon: <Zap size={18} className="opacity-90" /> },
    { name: 'Tools', path: '/tools', icon: <Terminal size={18} /> },
    { name: 'Vulnerabilities', path: '/vulnerabilities', icon: <AlertCircle size={18} /> },
    { name: 'Reports', path: '/reports', icon: <FileText size={18} /> },
  ];

  const isActive = (path: string) => location.pathname === path;

  const handleRestrictedClick = (e: React.MouseEvent, path: string, name: string) => {
    const token = localStorage.getItem('accessToken');
    const workspaceId = localStorage.getItem('workspaceId');
    const isValid = token && token !== 'undefined' && token !== 'null' && workspaceId && workspaceId !== 'undefined' && workspaceId !== 'null';

    const restrictedPaths = ['/ai-scanner', '/reports'];

    if (!isValid && restrictedPaths.includes(path)) {
      e.preventDefault();
      setAttemptedRoute(name);
      setShowAuthModal(true);
    }
  };

  return (
    <>
      <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-950/80 backdrop-blur-xl border-b border-slate-800/50 px-8 py-3 flex items-center justify-between h-20">
        <Link to="/" className="flex items-center gap-4 group">
          <div className="relative flex items-center justify-center h-14 w-14 rounded-2xl bg-slate-900/60 border border-slate-800 group-hover:border-brand/40 transition-all duration-500 shadow-2xl">
            <div className="absolute inset-0 bg-brand/10 opacity-0 group-hover:opacity-100 blur-xl transition-opacity"></div>
            <img
              src={logo}
              alt="RedVapt"
              className="w-11 h-11 object-contain relative z-10 drop-shadow-[0_0_18px_rgba(238, 67, 68,0.45)] transition-transform duration-500 group-hover:scale-110"
            />
          </div>
          <div className="flex flex-col">
            <span className="text-2xl font-black bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400 tracking-tighter leading-none">
              RedVapt
            </span>
          </div>
        </Link>

        <div className="hidden lg:flex items-center gap-1 bg-slate-900/50 p-1 rounded-full border border-slate-800">
          {navItems.map((item) => (
            <Link
              key={item.name}
              to={item.path}
              onClick={(e) => handleRestrictedClick(e, item.path, item.name)}
              className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-all ${isActive(item.path)
                ? 'bg-brand text-white shadow-lg shadow-brand/25'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
            >
              {item.icon}
              {item.name}
              {item.name === 'AI Scanner' && (
                <span className="text-[8px] font-bold bg-brand/90 text-white px-1.5 py-0.5 rounded ml-1">AI</span>
              )}
              {(item.name === 'AI Scanner' || item.name === 'Reports') && !localStorage.getItem('accessToken') && (
                <Lock size={12} className="ml-1 opacity-50" />
              )}
            </Link>
          ))}
        </div>

        <div className="flex items-center gap-4">
          <Link to="/login" className="hidden sm:inline-flex items-center px-6 py-2 rounded-full text-sm font-bold text-slate-400 hover:text-white border border-slate-800 hover:border-slate-700 hover:bg-slate-900/50 transition-all">
            Login
          </Link>
          <Link to="/book-demo" className="bg-brand hover:bg-red-700 text-white px-6 py-2 rounded-full text-sm font-bold shadow-lg shadow-brand/30 hover:scale-[1.02] transition-transform flex items-center gap-2">
            <Zap size={16} />
            Book Demo
          </Link>
        </div>
      </nav>

      {/* Professional Auth Modal */}
      {showAuthModal && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="bg-[#0a0d12] border border-[#1e262e] rounded-2xl p-6 max-w-md w-full shadow-2xl relative overflow-hidden">
            {/* Decorative glow */}
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-32 h-32 bg-brand/20 blur-[50px] -z-10"></div>

            <button
              onClick={() => setShowAuthModal(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white transition-colors"
            >
              <X size={20} />
            </button>

            <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-slate-900 border border-slate-800 mb-6 shadow-inner mx-auto">
              <Lock className="text-brand" size={24} />
            </div>

            <h2 className="text-xl font-bold text-white text-center mb-2">Access Restricted</h2>
            <p className="text-sm text-slate-400 text-center mb-8 px-4 leading-relaxed">
              The <strong className="text-white">{attemptedRoute}</strong> and professional reporting tools can only be used if you are logged in.
              Please sign in to your workspace to utilize automated penetration testing.
            </p>

            <div className="flex gap-3">
              <button
                onClick={() => setShowAuthModal(false)}
                className="flex-1 px-4 py-3 rounded-lg text-sm font-bold text-slate-300 hover:text-white bg-slate-800/50 hover:bg-slate-800 border border-slate-700 transition-all"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  setShowAuthModal(false);
                  navigate('/login');
                }}
                className="flex-1 px-4 py-3 rounded-lg text-sm font-bold text-white bg-brand hover:bg-red-700 shadow-lg shadow-brand/25 transition-all"
              >
                Log In
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default Navbar;
