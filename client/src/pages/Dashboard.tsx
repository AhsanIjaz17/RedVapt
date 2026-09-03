
import React, { useState, useEffect } from 'react';
import { Activity, ShieldAlert, Globe, CheckCircle2, Zap, ArrowRight, Server, Database, Lock, Search, Terminal, Cpu, Bug, Eye } from 'lucide-react';

const PythonCodeLine = ({ text, delay }: { text: string; delay: number }) => (
  <div className="flex gap-3 text-xs md:text-sm" style={{ animation: `fadeIn 0.5s ease-out ${delay}s both` }}>
    <span className="text-slate-600 select-none">{">>>"}</span>
    <span className="text-brand font-mono">{text}</span>
  </div>
);

const StatCard = ({ icon: Icon, title, value, subtext, trend, colorClass, textClass }: any) => (
  <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-3xl relative overflow-hidden group hover:border-brand/50 hover:bg-slate-900/60 transition-all duration-500 hover:-translate-y-1">
    <div className={`absolute top-0 right-0 w-32 h-32 opacity-10 rounded-full -mr-8 -mt-8 ${colorClass} blur-2xl group-hover:scale-125 transition-transform duration-700`}></div>
    <div className="flex justify-between items-start mb-6">
      <div className={`p-4 rounded-2xl ${colorClass} bg-opacity-20 group-hover:rotate-12 transition-transform`}>
        <Icon size={24} className={textClass} />
      </div>
      {trend && (
        <span className={`text-xs px-2 py-1 rounded-full font-bold ${trend > 0 ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}`}>
          {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
        </span>
      )}
    </div>
    <p className="text-slate-400 text-xs font-bold uppercase tracking-widest mb-1">{title}</p>
    <h3 className="text-4xl font-black mb-2 tracking-tighter">{value}</h3>
    <p className="text-xs text-slate-500">{subtext}</p>
  </div>
);

const Dashboard: React.FC = () => {
  const [scanProgress, setScanProgress] = useState(88);
  const [logs, setLogs] = useState<string[]>([]);

  useEffect(() => {
    const logInterval = setInterval(() => {
      const messages = [
        "Initializing Python worker @ node_04...",
        "Target handshake confirmed via SSL/TLS 1.3",
        "Agent [ORCHESTRATOR] assigning recon tasks...",
        "Crawling DOM for dynamic elements...",
        "SQLi payload validation: bypass attempt 4",
        "Analyzing response entropy for session ID...",
        "Gemini 3 Pro: Reasoning exploit path success 94%",
      ];
      setLogs(prev => [messages[Math.floor(Math.random() * messages.length)], ...prev].slice(0, 5));
    }, 2000);
    return () => clearInterval(logInterval);
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      setScanProgress(p => (p > 98 ? 75 : p + Math.random()));
    }, 100);
    return () => clearInterval(interval);
  }, []);

  const industryItems = [
    { id: 'fin', title: 'Financial Services', desc: 'PCI-DSS mapping, session token entropy analysis, and IDOR prevention.', img: 'https://images.unsplash.com/photo-1450101499163-c8848c66ca85?auto=format&fit=crop&q=80&w=800', tagBg: 'bg-blue-500/20', tagText: 'text-blue-400' },
    { id: 'health', title: 'Healthcare', desc: 'HIPAA compliance auditing, broken access control, and legacy system probing.', img: 'https://images.unsplash.com/photo-1519494026892-80bbd2d6fd0d?auto=format&fit=crop&q=80&w=800', tagBg: 'bg-green-500/20', tagText: 'text-green-400' },
    { id: 'saas', title: 'Enterprise SaaS', desc: 'Multi-tenant isolation testing, JWT verification, and API rate limit bypass.', img: 'https://images.unsplash.com/photo-1551434678-e076c223a692?auto=format&fit=crop&q=80&w=800', tagBg: 'bg-brand/15', tagText: 'text-red-300' },
    { id: 'gov', title: 'Government', desc: 'Air-gapped simulation, critical infrastructure auditing, and state-actor emulation.', img: 'https://images.unsplash.com/photo-1521295121783-8a321d551ad2?auto=format&fit=crop&q=80&w=800', tagBg: 'bg-brand/20', tagText: 'text-brand' },
    { id: 'shop', title: 'E-Commerce', desc: 'Shopping cart logic bypass, gift card enumeration, and pricing injection.', img: 'https://images.unsplash.com/photo-1472851294608-062f824d29cc?auto=format&fit=crop&q=80&w=800', tagBg: 'bg-brand/15', tagText: 'text-red-400' },
    { id: 'crypto', title: 'Web3 & Crypto', desc: 'Smart contract vulnerability scanning and hot-wallet exposure auditing.', img: 'https://images.unsplash.com/photo-1639762681485-074b7f938ba0?auto=format&fit=crop&q=80&w=800', tagBg: 'bg-brand/15', tagText: 'text-red-400' },
  ];

  return (
    <div className="pt-24 pb-20 px-6 max-w-7xl mx-auto space-y-16">
      {/* Dynamic Hero Section */}
      <section className="relative min-h-[500px] flex flex-col lg:flex-row items-center justify-between gap-12 rounded-[3rem] bg-slate-950/50 border border-slate-800 p-12 backdrop-blur-xl overflow-hidden group">
        <div className="absolute top-0 right-0 w-[50%] h-full bg-brand/5 blur-[120px] rounded-full -mr-32"></div>

        <div className="relative z-10 flex-1 space-y-10">
          <div className="inline-flex items-center gap-3 px-4 py-2 rounded-full bg-brand/10 border border-brand/20 text-red-400 text-xs font-black uppercase tracking-widest shadow-lg shadow-brand/15">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-brand"></span>
            </span>
            Python Multi-Agent Framework v2.4
          </div>

          <h1 className="text-6xl lg:text-8xl font-black leading-none tracking-tighter text-white">
            Autonomous <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-brand via-red-500 to-red-300 animate-gradient">
              Cyber Warfare
            </span>
          </h1>

          <p className="text-slate-400 text-xl max-w-xl leading-relaxed font-medium">
            RedVapt orchestrates specialized Python workers to map, probe, and validate your attack surface using collaborative intelligence.
          </p>

          <div className="flex flex-wrap gap-4 pt-4">
            <button className="px-10 py-5 bg-brand hover:bg-red-700 text-white rounded-2xl font-black shadow-2xl shadow-brand/30 transition-all hover:scale-105 active:scale-95 flex items-center gap-3">
              <Zap size={22} /> START MISSION
            </button>
            <button className="px-10 py-5 bg-slate-900/50 border border-slate-800 hover:border-slate-700 text-white rounded-2xl font-black transition-all hover:bg-slate-900">
              EXPLORE AGENTS
            </button>
          </div>
        </div>

        <div className="relative flex-1 hidden lg:block w-full">
          <div className="bg-slate-900/80 backdrop-blur-2xl border border-slate-800 rounded-[2.5rem] p-8 shadow-2xl transform rotate-1 group-hover:rotate-0 transition-transform duration-1000">
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-brand/15 rounded-lg"><Terminal size={18} className="text-red-300" /></div>
                <h3 className="text-sm font-black uppercase tracking-widest text-slate-300">Live Agent Feed</h3>
              </div>
              <div className="flex gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-slate-800"></div>
                <div className="w-2.5 h-2.5 rounded-full bg-slate-800"></div>
                <div className="w-2.5 h-2.5 rounded-full bg-green-500 animate-pulse"></div>
              </div>
            </div>

            <div className="space-y-4 font-mono">
              {logs.map((log, i) => (
                <div key={i} className={`text-[11px] p-3 rounded-xl border border-white/5 bg-white/[0.02] flex items-center gap-3 ${i === 0 ? 'text-red-400 translate-x-1' : 'text-slate-500'} transition-all`}>
                  <span className="opacity-30">[{new Date().toLocaleTimeString().split(' ')[0]}]</span>
                  {log}
                </div>
              ))}
              <div className="pt-4 flex gap-2 overflow-hidden">
                <div className="h-1 flex-1 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-brand animate-progress-fast"></div>
                </div>
                <div className="h-1 w-12 bg-brand rounded-full animate-pulse"></div>
              </div>
            </div>
          </div>
          <div className="absolute -bottom-10 -right-10 bg-brand/10 p-12 rounded-full blur-[80px]"></div>
        </div>
      </section>

      {/* Modern Stats Grid */}
      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
        <StatCard icon={Activity} title="Total Scans" value="2,491" subtext="Global operations" trend={14} colorClass="bg-blue-500" textClass="text-blue-400" />
        <StatCard icon={ShieldAlert} title="Vulnerabilities" value="152" subtext="Pending validation" trend={-8} colorClass="bg-red-500" textClass="text-red-400" />
        <StatCard icon={Cpu} title="CPU Cycles" value="84.2%" subtext="Agent resource load" trend={2} colorClass="bg-brand" textClass="text-red-400" />
        <StatCard icon={CheckCircle2} title="Auto-Resolved" value="812" subtext="Verified patched" trend={31} colorClass="bg-green-500" textClass="text-green-400" />
      </section>

      {/* Advanced Scan Progress with Python Stages */}
      <section className="bg-slate-950/40 border border-slate-800 rounded-[3rem] p-12 relative overflow-hidden group">
        <div className="absolute inset-0 bg-gradient-to-br from-brand/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity"></div>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-8 mb-12">
          <div className="flex items-center gap-6">
            <div className="p-5 bg-brand/10 rounded-3xl text-brand shadow-inner group-hover:scale-110 transition-transform">
              <Zap size={32} />
            </div>
            <div>
              <h3 className="text-3xl font-black tracking-tight">Operation: NEON_PHANTOM</h3>
              <p className="text-slate-500 font-medium">Real-time status of distributed Python worker pool</p>
            </div>
          </div>
          <div className="text-right">
            <p className="text-slate-600 text-[10px] font-black uppercase tracking-widest mb-1">Worker Load</p>
            <div className="flex gap-1">
              {[...Array(8)].map((_, i) => (
                <div key={i} className={`w-1.5 h-6 rounded-full ${i < 6 ? 'bg-brand/50' : 'bg-slate-800'}`}></div>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-10">
          <div className="relative w-full h-6 bg-slate-900 rounded-full p-1 shadow-inner overflow-hidden">
            <div
              className="absolute top-1 left-1 bottom-1 bg-gradient-to-r from-brand via-red-500 to-red-700 transition-all duration-300 ease-out rounded-full shadow-[0_0_24px_rgba(238, 67, 68,0.35)]"
              style={{ width: `calc(${scanProgress}% - 8px)` }}
            >
              <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')] opacity-20"></div>
              <div className="absolute inset-y-0 right-0 w-32 bg-white/20 blur-xl animate-pulse"></div>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-5 gap-6 text-xs font-black uppercase tracking-widest">
            {[
              { n: 'DNS Recon', v: 20 },
              { n: 'Port Map', v: 45 },
              { n: 'Fuzzing', v: 65 },
              { n: 'Sqli Check', v: 85 },
              { n: 'Reporting', v: 95 }
            ].map((stage, i) => (
              <div key={i} className={`flex flex-col gap-3 p-4 rounded-2xl border transition-all ${scanProgress > stage.v ? 'bg-brand/5 border-brand/20 text-brand' : 'bg-slate-900/40 border-slate-800 text-slate-600'}`}>
                <span className="flex items-center justify-between">
                  {stage.n}
                  {scanProgress > stage.v && <CheckCircle2 size={14} className="animate-bounce" />}
                </span>
                <div className="h-1 bg-current opacity-20 rounded-full"></div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Expanded Industry Solutions with Moving Hover Backdrops */}
      <section className="py-20">
        <div className="text-center mb-20 space-y-4">
          <span className="px-5 py-1.5 bg-brand/10 border border-brand/25 text-red-300 text-xs font-black rounded-full uppercase tracking-[0.3em] inline-block">Industry Grid</span>
          <h2 className="text-5xl lg:text-7xl font-black text-white tracking-tighter">Security for <span className="text-brand">Every Vertical</span></h2>
          <p className="text-slate-500 text-xl max-w-2xl mx-auto font-medium">Specialized payloads and logic agents for industry-specific threat models.</p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
          {industryItems.map((item) => (
            <div key={item.id} className="group relative h-[400px] rounded-[2.5rem] overflow-hidden border border-slate-800 hover:border-brand/50 transition-all duration-700">
              <div className="absolute inset-0 scale-100 group-hover:scale-110 transition-transform duration-1000 grayscale group-hover:grayscale-0">
                <img src={item.img} className="w-full h-full object-cover opacity-30 group-hover:opacity-60 transition-opacity" alt={item.title} />
              </div>
              <div className="absolute inset-0 bg-gradient-to-t from-slate-950 via-slate-950/40 to-transparent"></div>
              <div className="absolute inset-0 p-10 flex flex-col justify-end gap-4 transform translate-y-8 group-hover:translate-y-0 transition-transform duration-500">
                <div className={`w-fit px-3 py-1 rounded ${item.tagBg} ${item.tagText} text-[10px] font-black uppercase tracking-widest`}>
                  {item.title}
                </div>
                <h3 className="text-3xl font-black text-white">{item.title}</h3>
                <p className="text-slate-400 text-sm leading-relaxed opacity-0 group-hover:opacity-100 transition-opacity duration-700">{item.desc}</p>
                <div className="pt-4 flex items-center gap-2 text-brand font-black text-xs uppercase tracking-widest opacity-0 group-hover:opacity-100 transition-opacity translate-x-4 group-hover:translate-x-0">
                  Learn Protocol <ArrowRight size={14} />
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Feature Highlighting Grid with Hover Effects */}
      <section className="grid lg:grid-cols-2 gap-20 items-center py-20">
        <div className="space-y-10">
          <div className="space-y-4">
            <span className="text-red-400 font-black tracking-[0.4em] text-xs uppercase">The Core Engine</span>
            <h2 className="text-5xl font-black leading-tight text-white">Full-Spectrum Offensive Visibility</h2>
            <p className="text-slate-400 text-lg leading-relaxed font-medium">
              RedVapt doesn't just scan; it understands. Each Python worker is powered by a specialized subset of security knowledge, coordinated by the Gemini 3 Pro reasoning engine.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-6">
            <div className="p-6 bg-slate-900/40 border border-slate-800 rounded-3xl group hover:bg-slate-900 transition-all">
              <p className="text-3xl font-black text-white mb-1">15ms</p>
              <p className="text-[10px] text-slate-500 uppercase font-black tracking-widest">Global Handshake</p>
            </div>
            <div className="p-6 bg-slate-900/40 border border-slate-800 rounded-3xl group hover:bg-slate-900 transition-all">
              <p className="text-3xl font-black text-white mb-1">98.4%</p>
              <p className="text-[10px] text-slate-500 uppercase font-black tracking-widest">Agent Accuracy</p>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="group p-8 bg-slate-950/50 border border-slate-800 rounded-[2rem] flex gap-6 hover:border-brand/50 transition-all hover:translate-x-3 cursor-default">
            <div className="p-4 rounded-2xl bg-brand/10 text-brand shadow-xl group-hover:scale-110 transition-transform h-fit">
              <Cpu size={28} />
            </div>
            <div>
              <h4 className="text-xl font-black text-white mb-2">Dynamic Payload Orchestration</h4>
              <p className="text-slate-500 text-sm leading-relaxed">Python-based payload generator that mutates based on server response patterns.</p>
            </div>
          </div>
          <div className="group p-8 bg-slate-950/50 border border-slate-800 rounded-[2rem] flex gap-6 hover:border-brand/50 transition-all hover:translate-x-3 cursor-default">
            <div className="p-4 rounded-2xl bg-brand/10 text-red-400 shadow-xl group-hover:scale-110 transition-transform h-fit">
              <Globe size={28} />
            </div>
            <div>
              <h4 className="text-xl font-black text-white mb-2">Distributed Recon Workers</h4>
              <p className="text-slate-500 text-sm leading-relaxed">Asynchronous asset discovery using Python asyncio for massive parallelization.</p>
            </div>
          </div>
          <div className="group p-8 bg-slate-950/50 border border-slate-800 rounded-[2rem] flex gap-6 hover:border-brand/50 transition-all hover:translate-x-3 cursor-default">
            <div className="p-4 rounded-2xl bg-brand/10 text-red-300 shadow-xl group-hover:scale-110 transition-transform h-fit">
              <Eye size={28} />
            </div>
            <div>
              <h4 className="text-xl font-black text-white mb-2">Heuristic Logic Analysis</h4>
              <p className="text-slate-500 text-sm leading-relaxed">Identifying complex business logic flaws that automated tools typically miss.</p>
            </div>
          </div>
          <div className="group p-8 bg-slate-950/50 border border-slate-800 rounded-[2rem] flex gap-6 hover:border-brand/50 transition-all hover:translate-x-3 cursor-default">
            <div className="p-4 rounded-2xl bg-green-500/10 text-green-400 shadow-xl group-hover:scale-110 transition-transform h-fit">
              <Lock size={28} />
            </div>
            <div>
              <h4 className="text-xl font-black text-white mb-2">Safe Exploitation Engine</h4>
              <p className="text-slate-500 text-sm leading-relaxed">Non-destructive vulnerability validation with cryptographic proof collection.</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Dashboard;
