
import React from 'react';
import { Terminal, Github, ExternalLink, Zap, Box, Code } from 'lucide-react';

const ToolItem = ({ name, description, category, stars, url }: any) => (
  <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl hover:bg-slate-900/60 transition-colors">
    <div className="flex justify-between items-start mb-4">
      <div className="p-2 bg-brand/10 rounded-lg">
        <Box size={20} className="text-brand" />
      </div>
      <div className="flex items-center gap-1 text-[10px] bg-slate-800 px-2 py-1 rounded text-slate-400">
        <Github size={10} />
        {stars}
      </div>
    </div>
    <span className="text-[10px] text-brand font-bold uppercase tracking-wider">{category}</span>
    <h3 className="text-lg font-bold mb-2 flex items-center gap-2">
      {name}
      <ExternalLink size={14} className="text-slate-600" />
    </h3>
    <p className="text-sm text-slate-500 mb-6">{description}</p>
    <button
      onClick={() => url && window.open(url, '_blank')}
      className="w-full py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs font-medium transition-colors"
    >
      View Integration
    </button>
  </div>
);

const Tools: React.FC = () => {
  const categories = ['All Tools', 'Recon', 'Exploitation', 'Analysis', 'Reporting'];

  return (
    <div className="pt-32 pb-20 px-6 max-w-7xl mx-auto">
      <div className="flex flex-col md:flex-row justify-between items-end mb-12 gap-6">
        <div>
          <h1 className="text-4xl font-bold mb-4">Security <span className="text-brand">Toolkit</span></h1>
          <p className="text-slate-400 max-w-xl">
            RedVapt integrates with the industry's most powerful open-source security tools to provide a unified pentesting experience.
          </p>
        </div>
        <div className="flex gap-2 overflow-x-auto pb-2 scrollbar-none">
          {categories.map(c => (
            <button key={c} className={`px-4 py-2 rounded-full text-xs font-medium whitespace-nowrap ${c === 'All Tools' ? 'bg-brand text-white' : 'bg-slate-900 text-slate-400 border border-slate-800'}`}>
              {c}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <ToolItem
          name="Nmap Engine"
          description="High-performance network discovery and security auditing integration."
          category="Recon"
          stars="25.4k"
          url="https://nmap.org/"
        />
        <ToolItem
          name="Amass Bridge"
          description="In-depth DNS enumeration and network mapping orchestration."
          category="Recon"
          stars="12k"
          url="https://github.com/owasp-amass/amass"
        />
        <ToolItem
          name="Nuclei Runner"
          description="Template-based vulnerability scanning at scale with AI filtering."
          category="Analysis"
          stars="18.9k"
          url="https://github.com/projectdiscovery/nuclei"
        />
        <ToolItem
          name="Burp Integration"
          description="Automated proxy and scanner extension for deep web analysis."
          category="Analysis"
          stars="Enterprise"
          url="https://portswigger.net/burp"
        />
        <ToolItem
          name="FFUF Master"
          description="Blazing fast web fuzzer integration for directory discovery."
          category="Recon"
          stars="8.5k"
          url="https://github.com/ffuf/ffuf"
        />
        <ToolItem
          name="Metasploit Core"
          description="The world's most used penetration testing framework bridge."
          category="Exploitation"
          stars="32.1k"
          url="https://www.metasploit.com/"
        />
        <ToolItem
          name="OWASP ZAP"
          description="Open source web app security scanner agent."
          category="Analysis"
          stars="10.2k"
          url="https://www.zaproxy.org/"
        />
        <ToolItem
          name="Custom Scripts"
          description="Deploy your own Python/Bash scripts across our agent fleet."
          category="Exploitation"
          stars="User Built"
          url="https://github.com/HarisSheikh012/RedVapt"
        />
      </div>

      <div className="mt-20 bg-gradient-to-br from-brand/10 to-red-950/20 border border-brand/20 rounded-3xl p-12 text-center">
        <Terminal size={48} className="mx-auto text-brand mb-6" />
        <h2 className="text-3xl font-bold mb-4">Want to build your own tool?</h2>
        <p className="text-slate-400 mb-8 max-w-2xl mx-auto">
          Our SDK allows developers to create custom RedVapt agents and tools that can be shared with the community.
        </p>
        <button className="bg-white text-slate-950 px-8 py-3 rounded-full font-bold flex items-center gap-2 mx-auto hover:bg-slate-200 transition-colors">
          <Code size={18} />
          Explore SDK Docs
        </button>
      </div>
    </div>
  );
};

export default Tools;
