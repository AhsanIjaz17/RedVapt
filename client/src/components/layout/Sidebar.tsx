import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { 
    LayoutDashboard, 
    Globe, 
    Zap, 
    ShieldAlert, 
    Crosshair, 
    FileText, 
    Settings, 
    LogOut,
    ChevronRight,
} from 'lucide-react';
import logo from '../../assets/logo.png';

const Sidebar: React.FC = () => {
    const navigate = useNavigate();

    const menuItems = [
        { name: 'Dashboard', path: '/workspace/dashboard', icon: LayoutDashboard },
        { name: 'Assets', path: '/workspace/assets', icon: Globe },
        { name: 'AI Scanner', path: '/workspace/scans', icon: Zap },
        { name: 'Findings', path: '/workspace/findings', icon: ShieldAlert },
        { name: 'Attack Surface', path: '/workspace/attack-surface', icon: Crosshair },
        { name: 'Reports', path: '/workspace/reports', icon: FileText },
        { name: 'Settings', path: '/workspace/settings', icon: Settings },
    ];

    const handleLogout = () => {
        localStorage.clear();
        navigate('/login');
    };

    return (
        <aside className="fixed left-0 top-0 z-20 flex h-screen w-64 flex-shrink-0 flex-col border-r border-zinc-800/90 bg-[var(--ws-surface)]">
            {/* Logo */}
            <div className="p-6 flex items-center gap-3">
                <div className="flex w-11 shrink-0 items-center justify-center rounded-xl border border-red-500/30 bg-red-500/10 p-1 shadow-md shadow-red-900/20">
                    <img src={logo} alt="RedVapt" className="w-full h-full object-contain" />
                </div>
                <div className="flex flex-col">
                    <span className="text-xl font-semibold tracking-tight text-white">REDVAPT</span>
                    <span className="-mt-1 text-[10px] font-semibold uppercase tracking-[0.2em] text-red-500/90">Workspace</span>
                </div>
            </div>

            {/* Navigation */}
            <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto scrollbar-none">
                {menuItems.map((item) => (
                    <NavLink
                        key={item.path}
                        to={item.path}
                        className={({ isActive }) =>
                            `group flex items-center gap-3 rounded-lg px-4 py-2.5 text-sm font-semibold transition-all ${
                                isActive
                                    ? 'border-l-2 border-red-500 bg-red-500/10 text-white shadow-md shadow-red-900/10'
                                    : 'text-zinc-400 hover:bg-zinc-800/60 hover:text-white'
                            }`
                        }
                    >
                        <item.icon size={20} strokeWidth={2.15} />
                        <span className="flex-1">{item.name}</span>
                        <ChevronRight size={14} className="opacity-0 group-hover:opacity-40 transition-opacity" />
                    </NavLink>
                ))}
            </nav>

            {/* Footer */}
            <div className="mt-auto border-t border-zinc-800/90 p-4">
                <button
                    onClick={handleLogout}
                    className="w-full flex items-center gap-3 px-4 py-2.5 text-sm font-medium text-red-400 hover:text-red-300 hover:bg-red-500/5 rounded-lg transition-all"
                >
                    <LogOut size={18} />
                    <span>Sign Out</span>
                </button>
                <div className="mt-4 flex items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-950/80 px-4 py-3">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-zinc-700 bg-zinc-800 text-xs font-semibold text-white">
                        JD
                    </div>
                    <div className="flex flex-col min-w-0">
                        <span className="text-xs font-bold text-white truncate">John Doe</span>
                        <span className="truncate text-[10px] text-zinc-500">Member</span>
                    </div>
                </div>
            </div>
        </aside>
    );
};

export default Sidebar;
