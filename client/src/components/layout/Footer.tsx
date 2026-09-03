
import React from 'react';
import { ShieldCheck, Github, Linkedin, Twitter, Youtube, Heart } from 'lucide-react';
import logo from '../../assets/logo.png';
import { Link } from 'react-router-dom';

const Footer: React.FC = () => {
  return (
    <footer className="bg-slate-950 border-t border-slate-800 pt-20 pb-10 px-6">
      <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-12 mb-16">
        <div className="col-span-1 space-y-6">
          <div className="flex items-center gap-3 group">
            <div className="relative flex items-center justify-center p-1.5 bg-slate-900 border border-slate-800 rounded-xl group-hover:border-brand/30 transition-colors">
              <img src={logo} alt="RedVapt" className="w-16 h-16 object-contain drop-shadow-[0_0_12px_rgba(244,114,114,0.4)]" />
            </div>
            <span className="text-2xl font-black text-white tracking-tighter">RedVapt</span>
          </div>
          <p className="text-slate-400 text-sm leading-relaxed font-medium">
            Advanced AI-powered penetration testing platform using autonomous Python orchestration for comprehensive enterprise security.
          </p>
          <div className="flex items-center gap-4">
            <a href="#" className="p-2.5 bg-slate-900 border border-slate-800 rounded-xl hover:bg-slate-800 transition-all hover:scale-110"><Github size={20} /></a>
            <a href="#" className="p-2.5 bg-slate-900 border border-slate-800 rounded-xl hover:bg-slate-800 transition-all hover:scale-110"><Linkedin size={20} /></a>
            <a href="#" className="p-2.5 bg-slate-900 border border-slate-800 rounded-xl hover:bg-slate-800 transition-all hover:scale-110"><Twitter size={20} /></a>
          </div>
        </div>

        <div>
          <h4 className="font-black mb-8 text-white uppercase text-xs tracking-widest">Capabilities</h4>
          <ul className="space-y-4 text-sm text-slate-500 font-medium">
            <li><Link to="/ai-scanner" className="hover:text-red-400 transition-colors">Autonomous Scanning</Link></li>
            <li><Link to="/" className="hover:text-red-400 transition-colors">Real-time Monitoring</Link></li>
            <li><Link to="/tools" className="hover:text-red-400 transition-colors">Python Agent SDK</Link></li>
            <li><Link to="/reports" className="hover:text-red-400 transition-colors">Vulnerability Reports</Link></li>
          </ul>
        </div>

        <div>
          <h4 className="font-black mb-8 text-white uppercase text-xs tracking-widest">Resources</h4>
          <ul className="space-y-4 text-sm text-slate-500 font-medium">
            <li><a href="#" className="hover:text-red-400 transition-colors">Documentation</a></li>
            <li><a href="#" className="hover:text-red-400 transition-colors">Agent API Docs</a></li>
            <li><a href="#" className="hover:text-red-400 transition-colors">Security Tutorials</a></li>
            <li><a href="#" className="hover:text-red-400 transition-colors">Compliance Guide</a></li>
          </ul>
        </div>

        <div>
          <h4 className="font-black mb-8 text-white uppercase text-xs tracking-widest">Legal</h4>
          <ul className="space-y-4 text-sm text-slate-500 font-medium">
            <li><Link to="/privacy" className="hover:text-red-400 transition-colors">Privacy Policy</Link></li>
            <li><Link to="/terms" className="hover:text-red-400 transition-colors">Terms of Service</Link></li>
            <li><a href="#" className="hover:text-red-400 transition-colors">Ethical Guidelines</a></li>
            <li><a href="#" className="hover:text-red-400 transition-colors">Bug Bounty</a></li>
          </ul>
        </div>
      </div>

      <div className="max-w-7xl mx-auto pt-10 border-t border-slate-900 flex flex-col md:flex-row items-center justify-between gap-8">
        <div className="text-[10px] text-slate-600 font-black uppercase tracking-[0.2em] text-center md:text-left">
          <p>© 2025 RedVapt Ecosystem. Final Year Technical Project.</p>
        </div>

        <div className="flex items-center gap-2">
          <p className="flex items-center gap-2 text-sm text-slate-400 font-bold">
            Made with <Heart size={16} className="text-red-500 fill-red-500 animate-pulse" /> by
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-brand to-red-600 font-black text-lg">RedVapt Team</span>
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
