
import React from 'react';
import { Target, Users, Shield, Cpu, Code, Globe, Search, Terminal, Zap, Layers, Server } from 'lucide-react';

const TechPill = ({ text }: { text: string }) => (
  <span className="px-3 py-1 bg-slate-800 border border-slate-700 rounded-full text-[10px] font-mono text-red-400 uppercase tracking-widest">
    {text}
  </span>
);

const About: React.FC = () => {
  return (
    <div className="pt-32 pb-20 px-6 max-w-7xl mx-auto space-y-32">
      <section className="flex flex-col lg:flex-row items-center gap-20">
        <div className="flex-1 space-y-10">
          <div className="space-y-4">
            <span className="px-5 py-2 bg-brand/10 text-brand text-xs font-black rounded-full border border-brand/20 uppercase tracking-[0.2em] inline-block">The Genesis</span>
            <h1 className="text-6xl lg:text-8xl font-black leading-none tracking-tighter text-white">
              Redefining <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-brand to-red-700">Offensive AI</span>
            </h1>
          </div>
          <p className="text-slate-400 text-xl leading-relaxed font-medium">
            RedVapt was built to bridge the gap between static vulnerability scanners and manual penetration testing. The platform leverages Python-based modularity to simulate complex adversarial behavior, providing a scalable and intelligent alternative to traditional security assessments.
          </p>
          <div className="flex flex-wrap gap-3">
            <TechPill text="Python 3.12" />
            <TechPill text="Gemini 3 Pro" />
            <TechPill text="AsyncIO" />
            <TechPill text="PyTorch Core" />
            <TechPill text="Dockerized Agents" />
          </div>
        </div>
        <div className="flex-1 relative group">
          <div className="absolute inset-0 bg-brand/15 blur-[100px] rounded-full group-hover:bg-brand/30 transition-colors"></div>
          <div className="relative bg-slate-950 border border-slate-800 p-10 rounded-[3rem] shadow-2xl transform hover:rotate-2 transition-transform duration-700">
            <div className="space-y-6">
              <div className="flex gap-2 mb-4">
                <div className="w-3 h-3 rounded-full bg-red-500/50"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500/50"></div>
                <div className="w-3 h-3 rounded-full bg-green-500/50"></div>
              </div>
              <div className="font-mono text-xs md:text-sm text-slate-400 space-y-3">
                <p className="text-brand">class AutonomousAgent(Worker):</p>
                <p className="pl-4">def __init__(self, brain=Gemini):</p>
                <p className="pl-8">self.orchestrator = brain</p>
                <p className="pl-8 text-slate-600"># Specialized Python logic</p>
                <p className="pl-8">self.modules = ['recon', 'fuzz', 'poc']</p>
                <p className="pl-4">async def execute(self, target):</p>
                <p className="pl-8">report = await self.probe(target)</p>
                <p className="pl-8">return self.brain.reason(report)</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="grid md:grid-cols-3 gap-10">
        {[
          { icon: Target, title: "Precision OSINT", color: "blue", desc: "Our agents use Python's Scapy and Request libraries to map attack surfaces with sub-millisecond precision." },
          { icon: Zap, title: "Neural Orchestration", color: "pink", desc: "Collaborative reasoning via Gemini 3 Pro allows agents to share context and chain vulnerabilities intelligently." },
          { icon: Shield, title: "Ethical Integrity", color: "green", desc: "Built with a 'Safe-First' philosophy, RedVapt ensures all probes are non-destructive and data-privacy focused." }
        ].map((item, idx) => (
          <div key={idx} className="bg-slate-900/30 border border-slate-800 p-12 rounded-[2.5rem] hover:border-slate-600 transition-all hover:-translate-y-2 group">
            <div className={`p-5 rounded-2xl w-fit mb-8 bg-${item.color}-500/10 text-${item.color}-400 group-hover:scale-110 transition-transform`}>
              <item.icon size={36} />
            </div>
            <h3 className="text-3xl font-black mb-4 text-white">{item.title}</h3>
            <p className="text-slate-500 leading-relaxed font-medium">
              {item.desc}
            </p>
          </div>
        ))}
      </section>

      <section className="bg-slate-950 border border-slate-800 rounded-[3rem] p-16 relative overflow-hidden group">
        <div className="absolute top-0 right-0 w-96 h-96 bg-brand/5 blur-[120px] rounded-full group-hover:scale-150 transition-transform duration-1000"></div>
        <div className="relative z-10 grid lg:grid-cols-2 gap-20 items-center">
          <div className="space-y-8">
            <h2 className="text-5xl font-black text-white tracking-tighter">The Agent Ecosystem</h2>
            <div className="space-y-6">
              {[
                { icon: Globe, name: "Recon Worker", tech: "BeautifulSoup / DNS-Python", desc: "Maps DNS, cloud infrastructure, and hidden endpoints." },
                { icon: Search, name: "Vuln Scanner", tech: "Nuclei Core / Custom Fuzzers", desc: "Identifies CVEs and logic flaws with minimal noise." },
                { icon: Server, name: "Logic Evaluator", tech: "PyJWT / Cryptography", desc: "Audits session management and authentication flow." },
              ].map((agent, i) => (
                <div key={i} className="flex gap-6 p-6 bg-slate-900/40 rounded-3xl border border-transparent hover:border-brand/30 transition-all">
                  <div className="p-3 bg-slate-950 rounded-xl text-brand h-fit">
                    <agent.icon size={22} />
                  </div>
                  <div>
                    <h4 className="font-bold text-white mb-1">{agent.name}</h4>
                    <p className="text-[10px] font-mono text-brand uppercase tracking-widest mb-2">{agent.tech}</p>
                    <p className="text-sm text-slate-500 font-medium">{agent.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="space-y-6">
            <div className="p-8 bg-slate-900/60 rounded-[2rem] border border-slate-800 space-y-4">
              <div className="flex items-center gap-2 mb-2">
                <Layers className="text-brand" size={20} />
                <h5 className="font-black text-xs uppercase tracking-widest text-slate-300">Platform Capabilities</h5>
              </div>
              <div className="flex flex-col gap-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-500">Recon Depth</span>
                  <span className="font-mono text-brand">5-Phase Methodology</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-500">Agent Intelligence</span>
                  <span className="font-mono text-red-300">ReAct Loop • 7 Specialists</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-500">Vulnerability Coverage</span>
                  <span className="font-mono text-red-400">OWASP Top 10 Aligned</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-500">Report Format</span>
                  <span className="font-mono text-green-400">HTML + JSON Export</span>
                </div>
              </div>
            </div>
            <p className="text-slate-500 text-sm italic text-center px-10 leading-relaxed font-medium">
              "RedVapt is not just a tool; it's a collaborative teammate for security professionals."
            </p>
          </div>

        </div>
      </section>
    </div>
  );
};

export default About;
