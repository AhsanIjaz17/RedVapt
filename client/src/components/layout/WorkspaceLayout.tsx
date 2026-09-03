import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import { 
    Search, 
    Bell, 
    ChevronDown, 
    Plus, 
    Zap, 
    ShieldCheck, 
    Target,
    Activity
} from 'lucide-react';

const WorkspaceLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const [scrolled, setScrolled] = useState(false);

    useEffect(() => {
        const handleScroll = () => setScrolled(window.scrollY > 20);
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    const pageTitle = location.pathname.split('/').pop()?.replace('-', ' ') || 'Dashboard';

    return (
        <div className="flex min-h-screen bg-[var(--ws-canvas)] text-zinc-200">
            <Sidebar />
            
            <main className="flex-1 ml-64 flex flex-col min-h-screen">
                {/* Header */}
                <header className={`sticky top-0 z-10 px-8 py-4 flex items-center justify-between transition-all duration-300 ${
                    scrolled ? 'border-b border-zinc-800/90 bg-zinc-950/85 shadow-lg shadow-black/25 backdrop-blur-xl' : 'bg-transparent'
                }`}>
                    <div className="flex items-center gap-4">
                        <h2 className="font-display text-lg font-bold uppercase tracking-[0.12em] text-zinc-50 sm:text-xl">{pageTitle}</h2>
                        <div className="h-5 w-px bg-zinc-800" />
                        <div className="flex items-center gap-2 px-3 py-1.5 bg-green-500/10 border border-green-500/20 text-green-400 text-xs font-bold rounded-full">
                            <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                            ENGINE ONLINE
                        </div>
                    </div>

                    <div className="flex items-center gap-6">
                        {/* Search */}
                        <div className="hidden w-64 items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/80 px-3 py-1.5 transition-all focus-within:border-red-500/35 lg:flex">
                            <Search size={18} strokeWidth={2} className="text-zinc-500" />
                            <input 
                                type="text" 
                                placeholder="Search workspace..." 
                                className="w-full border-none bg-transparent text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none"
                            />
                            <div className="flex items-center gap-1 rounded border border-zinc-800 bg-zinc-950 px-1 text-[10px] text-zinc-500">
                                <span>⌘</span><span>K</span>
                            </div>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center gap-3">
                            <button type="button" className="relative p-2 text-zinc-500 transition-colors hover:text-zinc-100">
                                <Bell size={22} strokeWidth={2} />
                                <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full border-2 border-[var(--ws-canvas)] bg-red-500" />
                            </button>
                            <div className="h-8 w-px bg-zinc-800" />
                            <button type="button" className="group flex items-center gap-2 rounded-xl border border-zinc-800 bg-zinc-900/80 py-1 pl-2 pr-1 transition-all hover:border-zinc-700">
                                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-gradient-to-br from-red-600 to-red-900 text-[10px] font-bold text-white">
                                    JD
                                </div>
                                <ChevronDown size={14} className="text-zinc-500 transition-colors group-hover:text-zinc-200" />
                            </button>
                        </div>
                    </div>
                </header>

                {/* Content */}
                <div className="p-8 flex-1">
                    {children}
                </div>

                {/* Simple Footer */}
                <footer className="flex items-center justify-between border-t border-zinc-800/90 px-8 py-6">
                    <p className="text-[10px] font-semibold uppercase tracking-widest text-zinc-600">
                        © 2026 RedVapt offensive security
                    </p>
                    <div className="flex items-center gap-6">
                        <a href="#" className="text-[10px] font-semibold uppercase tracking-widest text-zinc-600 transition-colors hover:text-red-400">API status</a>
                        <a href="#" className="text-[10px] font-semibold uppercase tracking-widest text-zinc-600 transition-colors hover:text-red-400">Support</a>
                    </div>
                </footer>
            </main>
        </div>
    );
};

export default WorkspaceLayout;
