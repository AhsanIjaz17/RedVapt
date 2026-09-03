import React, { useState } from 'react';
import { Lock, Mail, Eye, ArrowRight, UserPlus, LogIn, ShieldCheck, AlertCircle, Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import logo from '../assets/logo.png';

const Login: React.FC = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const navigate = useNavigate();

  const toggleMode = () => {
    setIsLogin(!isLogin);
    setError(null);
    setSuccess(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setIsLoading(true);

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
      const body = isLogin
        ? { email, password }
        : { email, password, name };

      const response = await fetch(`http://localhost:3001${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Authentication failed');
      }

      if (!isLogin) {
        setIsLogin(true);
        setSuccess('Registration successful! Please sign in to continue.');
        return;
      }

      // Store token and workspace info
      localStorage.setItem('accessToken', data.accessToken);
      if (data.workspaceId) {
        localStorage.setItem('workspaceId', data.workspaceId);
      } else if (data.workspace?.id) {
        localStorage.setItem('workspaceId', data.workspace.id);
      }

      // Redirect to workspace dashboard
      navigate('/workspace/dashboard');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-6 py-20 relative bg-[#020617]">
      {/* Background Orbs */}
      <div className="absolute top-[-10%] right-[-10%] w-[50%] h-[50%] bg-brand/10 blur-[120px] rounded-full pointer-events-none"></div>
      <div className="absolute bottom-[-10%] left-[-10%] w-[50%] h-[50%] bg-brand/10 blur-[120px] rounded-full pointer-events-none"></div>

      <div className="w-full max-w-[440px] relative z-10">
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center mb-6 relative group">
            <div className="absolute inset-0 bg-brand/20 blur-2xl rounded-full scale-150 opacity-50 group-hover:opacity-100 transition-opacity"></div>
            <img
              src={logo}
              alt="RedVapt"
              className="w-24 h-24 object-contain relative z-10"
            />
          </div>
          <h1 className="text-4xl font-black mb-2 tracking-tighter text-white">
            {isLogin ? 'Welcome Back' : 'Create Account'}
          </h1>
          <p className="text-slate-400 font-medium tracking-tight">
            {isLogin
              ? 'Secure access to the RedVapt platform'
              : 'Join the next generation of security testing'}
          </p>
        </div>

        <div className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8 md:p-10 backdrop-blur-2xl shadow-2xl">
          {/* Enhanced Tab Switcher */}
          <div className="flex p-1.5 bg-slate-950/80 border border-slate-800/80 rounded-2xl mb-8 relative">
            <button
              type="button"
              onClick={() => { setIsLogin(true); setError(null); }}
              className={`flex-1 py-3 text-sm font-black uppercase tracking-widest rounded-xl transition-all duration-300 relative z-10 ${isLogin ? 'text-white' : 'text-slate-500 hover:text-slate-300'}`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => { setIsLogin(false); setError(null); }}
              className={`flex-1 py-3 text-sm font-black uppercase tracking-widest rounded-xl transition-all duration-300 relative z-10 ${!isLogin ? 'text-white' : 'text-slate-500 hover:text-slate-300'}`}
            >
              Register
            </button>
            <div
              className="absolute top-1.5 bottom-1.5 w-[calc(50%-6px)] bg-brand rounded-xl transition-all duration-300 ease-out z-0 shadow-lg shadow-brand/25"
              style={{ left: isLogin ? '6px' : 'calc(50%)' }}
            ></div>
          </div>

          {success && (
            <div className="mb-6 p-4 bg-green-500/10 border border-green-500/20 rounded-2xl flex items-center gap-3 text-green-400 text-sm">
              <ShieldCheck size={18} className="shrink-0" />
              <p className="font-medium">{success}</p>
            </div>
          )}

          {error && (
            <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-2xl flex items-center gap-3 text-red-400 text-sm animate-shake">
              <AlertCircle size={18} className="shrink-0" />
              <p className="font-medium">{error}</p>
            </div>
          )}

          <form className="space-y-5" onSubmit={handleSubmit}>
            {!isLogin && (
              <div>
                <label htmlFor="full-name" className="block text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-2 px-1">Full Name</label>
                <div className="relative group">
                  <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600 group-focus-within:text-brand transition-colors">
                    <UserPlus size={18} />
                  </div>
                  <input
                    id="full-name"
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="John Doe"
                    className="w-full bg-slate-950/50 border border-slate-800 rounded-2xl py-3.5 pl-12 pr-4 text-slate-200 focus:outline-none focus:ring-2 focus:ring-brand/25 focus:border-brand/50 transition-all placeholder:text-slate-700"
                  />
                </div>
              </div>
            )}

            <div>
              <label htmlFor="email" className="block text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-2 px-1">Email Address</label>
              <div className="relative group">
                <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600 group-focus-within:text-brand transition-colors">
                  <Mail size={18} />
                </div>
                <input
                  id="email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@company.com"
                  className="w-full bg-slate-950/50 border border-slate-800 rounded-2xl py-3.5 pl-12 pr-4 text-slate-200 focus:outline-none focus:ring-2 focus:ring-brand/25 focus:border-brand/50 transition-all placeholder:text-slate-700"
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between items-center mb-2 px-1">
                <label htmlFor="password" className="block text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">Password</label>
                {isLogin && <button type="button" className="text-[10px] text-brand font-bold hover:text-red-300 transition-colors">Forgot password?</button>}
              </div>
              <div className="relative group">
                <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600 group-focus-within:text-brand transition-colors">
                  <Lock size={18} />
                </div>
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-slate-950/50 border border-slate-800 rounded-2xl py-3.5 pl-12 pr-12 text-slate-200 focus:outline-none focus:ring-2 focus:ring-brand/25 focus:border-brand/50 transition-all placeholder:text-slate-700"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400 transition-colors"
                >
                  <Eye size={18} />
                </button>
              </div>
            </div>

            <button
              disabled={isLoading}
              className="w-full py-4 bg-brand hover:bg-red-700 disabled:bg-slate-800 disabled:cursor-not-allowed text-white rounded-2xl font-black shadow-xl shadow-brand/25 transition-all active:scale-[0.98] flex items-center justify-center gap-2 mt-2"
            >
              {isLoading ? (
                <Loader2 className="animate-spin" size={20} />
              ) : (
                isLogin ? <LogIn size={20} /> : <UserPlus size={20} />
              )}
              {isLoading ? 'Processing...' : (isLogin ? 'Sign In' : 'Create Account')}
            </button>
          </form>

          <div className="relative my-8">
            <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-slate-800"></div></div>
            <div className="relative flex justify-center text-[10px] uppercase tracking-[0.3em] text-slate-600 font-black">
              <span className="bg-[#0f172a] px-4">Trusted Authentication</span>
            </div>
          </div>

          <div className="p-4 bg-slate-950/50 border border-slate-800 rounded-2xl text-center">
            <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest">
              Experimental Workspace Access
            </p>
          </div>
        </div>

        <div className="mt-10 p-6 bg-brand/5 border border-brand/15 rounded-3xl flex items-center gap-4">
          <div className="p-3 bg-brand/20 rounded-2xl">
            <ShieldCheck className="text-brand" size={24} />
          </div>
          <div>
            <p className="text-[10px] font-black text-brand uppercase tracking-widest mb-0.5">Enterprise Security</p>
            <p className="text-xs text-slate-500 font-medium leading-tight">SOC2 Type II Compliant. AES-256 encrypted session management and hardware isolated keys.</p>
          </div>
        </div>

        {/* Registration toggle has moved to the prominent tabs at the top of the form */}
      </div>
    </div>
  );
};

export default Login;
