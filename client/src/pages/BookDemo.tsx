
import React from 'react';
import { Calendar, User, Building, MessageSquare, Zap, CheckCircle2 } from 'lucide-react';

const BookDemo: React.FC = () => {
  return (
    <div className="pt-32 pb-20 px-6 max-w-7xl mx-auto flex flex-col lg:flex-row gap-16">
      <div className="flex-1">
        <span className="text-brand font-bold tracking-widest text-xs uppercase mb-4 block">Product Walkthrough</span>
        <h1 className="text-6xl font-bold mb-8 leading-tight">See RedVapt <br /> in <span className="text-brand">Action</span></h1>
        <p className="text-slate-400 text-xl mb-12">
          Join our security experts for a personalized demo. Learn how RedVapt's AI agents can secure your specific infrastructure.
        </p>

        <div className="space-y-6">
          <div className="flex gap-4">
            <div className="p-3 bg-brand/10 rounded-xl text-brand"><Zap size={24} /></div>
            <div>
              <h4 className="font-bold text-lg">Full Platform Tour</h4>
              <p className="text-slate-500">Explore the dashboard, AI scanner, and report generator.</p>
            </div>
          </div>
          <div className="flex gap-4">
            <div className="p-3 bg-green-500/10 rounded-xl text-green-400"><CheckCircle2 size={24} /></div>
            <div>
              <h4 className="font-bold text-lg">Custom Strategy</h4>
              <p className="text-slate-500">Discuss how to integrate RedVapt into your existing DevSecOps pipeline.</p>
            </div>
          </div>
          <div className="flex gap-4">
             <div className="p-3 bg-blue-500/10 rounded-xl text-blue-400"><MessageSquare size={24} /></div>
             <div>
               <h4 className="font-bold text-lg">Q&A with Security Engineers</h4>
               <p className="text-slate-500">Get technical answers to your security and compliance questions.</p>
             </div>
          </div>
        </div>
      </div>

      <div className="flex-1 bg-slate-900/40 border border-slate-800 p-10 rounded-[2.5rem] backdrop-blur-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-32 h-32 bg-brand/10 blur-[60px] rounded-full"></div>
        
        <form className="space-y-6 relative z-10">
          <div className="grid grid-cols-2 gap-6">
            <div>
              <label className="block text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">First Name</label>
              <div className="relative">
                <User className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-700" size={16} />
                <input type="text" placeholder="John" className="w-full bg-slate-950 border border-slate-800 rounded-2xl py-3 pl-12 pr-4 text-sm focus:outline-none focus:border-brand" />
              </div>
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Last Name</label>
              <input type="text" placeholder="Doe" className="w-full bg-slate-950 border border-slate-800 rounded-2xl py-3 px-4 text-sm focus:outline-none focus:border-brand" />
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Work Email</label>
            <input type="email" placeholder="john@company.com" className="w-full bg-slate-950 border border-slate-800 rounded-2xl py-3 px-4 text-sm focus:outline-none focus:border-brand" />
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Company Name</label>
            <div className="relative">
              <Building className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-700" size={16} />
              <input type="text" placeholder="CyberSecure Inc." className="w-full bg-slate-950 border border-slate-800 rounded-2xl py-3 pl-12 pr-4 text-sm focus:outline-none focus:border-brand" />
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Preferred Date</label>
            <div className="relative">
              <Calendar className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-700" size={16} />
              <input type="date" className="w-full bg-slate-950 border border-slate-800 rounded-2xl py-3 pl-12 pr-4 text-sm focus:outline-none focus:border-brand text-slate-400" />
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Message (Optional)</label>
            <textarea rows={3} placeholder="Tell us about your security needs..." className="w-full bg-slate-950 border border-slate-800 rounded-2xl py-3 px-4 text-sm focus:outline-none focus:border-brand"></textarea>
          </div>

          <button className="w-full py-4 bg-gradient-to-r from-brand to-red-800 hover:from-red-600 hover:to-red-900 text-white rounded-2xl font-bold text-lg shadow-xl shadow-brand/25 transition-all active:scale-95">
            Schedule Demo
          </button>
          
          <p className="text-[10px] text-center text-slate-600 uppercase tracking-widest font-bold">
            Guaranteed response within 24 hours
          </p>
        </form>
      </div>
    </div>
  );
};

export default BookDemo;
