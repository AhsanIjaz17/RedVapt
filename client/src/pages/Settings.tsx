import React, { useState, useEffect } from 'react';
import { User, Shield, Key, LogOut, Mail, Calendar, Building2, Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const BACKEND_URL = 'http://localhost:3001';

interface UserInfo {
    id: string;
    email: string;
    name: string;
}

interface WorkspaceInfo {
    id: string;
    name: string;
    role: string;
}

const Settings: React.FC = () => {
    const [user, setUser] = useState<UserInfo | null>(null);
    const [workspace, setWorkspace] = useState<WorkspaceInfo | null>(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        const fetchInfo = async () => {
            try {
                const token = localStorage.getItem('accessToken');
                const workspaceId = localStorage.getItem('workspaceId');
                if (!token || !workspaceId) return;

                // Parse user info from JWT
                try {
                    const payload = JSON.parse(atob(token.split('.')[1]));
                    setUser({ id: payload.userId || '', email: payload.email || '', name: payload.name || '' });
                } catch { /* ignore */ }

                // Fetch workspace info
                const res = await fetch(`${BACKEND_URL}/api/workspaces/my`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (res.ok) {
                    const workspaces = await res.json();
                    const current = workspaces.find((w: any) => w.id === workspaceId) || workspaces[0];
                    if (current) {
                        setWorkspace({ id: current.id, name: current.name, role: current.role });
                    }
                }
            } catch (err) {
                console.error('Failed to fetch settings', err);
            } finally {
                setLoading(false);
            }
        };
        fetchInfo();
    }, []);

    const handleSignOut = () => {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('workspaceId');
        navigate('/login');
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center py-20">
                <Loader2 size={28} className="text-brand animate-spin" />
                <span className="ml-3 text-[#6b7280]">Loading settings...</span>
            </div>
        );
    }

    return (
        <div className="space-y-6 max-w-3xl">
            {/* Header */}
            <div>
                <h1 className="text-2xl font-black text-white tracking-tight">Settings</h1>
                <p className="text-sm text-[#6b7280] mt-1">Manage your account and workspace preferences.</p>
            </div>

            {/* Profile Section */}
            <div className="bg-[#0f1418]/60 border border-[#1e262e] rounded-xl p-6">
                <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 bg-brand/10 rounded-lg"><User size={16} className="text-brand" /></div>
                    <h2 className="text-sm font-bold text-white uppercase tracking-wider">Account Profile</h2>
                </div>

                <div className="space-y-4">
                    <div className="flex items-center gap-4 p-4 bg-[#0a0d12] rounded-xl border border-[#1e262e]">
                        <div className="w-14 h-14 rounded-xl bg-brand flex items-center justify-center text-white font-bold text-xl">
                            {(user?.name || user?.email || '?').charAt(0).toUpperCase()}
                        </div>
                        <div>
                            <p className="text-base font-bold text-white">{user?.name || 'User'}</p>
                            <p className="text-sm text-[#6b7280] flex items-center gap-1.5 mt-0.5">
                                <Mail size={12} />{user?.email || 'No email'}
                            </p>
                        </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div className="p-4 bg-[#0a0d12] rounded-xl border border-[#1e262e]">
                            <p className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider mb-1">User ID</p>
                            <p className="text-xs text-[#9ca3af] font-mono truncate">{user?.id || '—'}</p>
                        </div>
                        <div className="p-4 bg-[#0a0d12] rounded-xl border border-[#1e262e]">
                            <p className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider mb-1">Auth Provider</p>
                            <p className="text-xs text-[#9ca3af] flex items-center gap-1.5"><Key size={12} /> Local (Email/Password)</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Workspace Section */}
            <div className="bg-[#0f1418]/60 border border-[#1e262e] rounded-xl p-6">
                <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 bg-brand/10 rounded-lg"><Building2 size={16} className="text-red-400" /></div>
                    <h2 className="text-sm font-bold text-white uppercase tracking-wider">Workspace</h2>
                </div>

                <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                        <div className="p-4 bg-[#0a0d12] rounded-xl border border-[#1e262e]">
                            <p className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider mb-1">Workspace Name</p>
                            <p className="text-sm text-white font-semibold">{workspace?.name || 'My Workspace'}</p>
                        </div>
                        <div className="p-4 bg-[#0a0d12] rounded-xl border border-[#1e262e]">
                            <p className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider mb-1">Your Role</p>
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-brand/15 text-brand rounded-lg text-xs font-bold uppercase">
                                <Shield size={12} />{workspace?.role || 'owner'}
                            </span>
                        </div>
                    </div>
                    <div className="p-4 bg-[#0a0d12] rounded-xl border border-[#1e262e]">
                        <p className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider mb-1">Workspace ID</p>
                        <p className="text-xs text-[#9ca3af] font-mono">{workspace?.id || localStorage.getItem('workspaceId') || '—'}</p>
                    </div>
                </div>
            </div>

            {/* Security Section */}
            <div className="bg-[#0f1418]/60 border border-[#1e262e] rounded-xl p-6">
                <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 bg-emerald-500/10 rounded-lg"><Shield size={16} className="text-emerald-400" /></div>
                    <h2 className="text-sm font-bold text-white uppercase tracking-wider">Security</h2>
                </div>

                <div className="space-y-3">
                    <div className="flex items-center justify-between p-4 bg-[#0a0d12] rounded-xl border border-[#1e262e]">
                        <div>
                            <p className="text-sm font-semibold text-white">Session Management</p>
                            <p className="text-xs text-[#6b7280] mt-0.5">JWT-based authentication with workspace scoping</p>
                        </div>
                        <span className="px-2.5 py-1 bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 rounded-lg text-[10px] font-bold uppercase">
                            Active
                        </span>
                    </div>
                    <div className="flex items-center justify-between p-4 bg-[#0a0d12] rounded-xl border border-[#1e262e]">
                        <div>
                            <p className="text-sm font-semibold text-white">Multi-Tenant Isolation</p>
                            <p className="text-xs text-[#6b7280] mt-0.5">Scans, reports, and findings are scoped to your workspace</p>
                        </div>
                        <span className="px-2.5 py-1 bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 rounded-lg text-[10px] font-bold uppercase">
                            Enforced
                        </span>
                    </div>
                </div>
            </div>

            {/* Sign Out */}
            <button
                onClick={handleSignOut}
                className="w-full flex items-center justify-center gap-2 py-3 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 hover:border-red-500/30 text-red-400 rounded-xl text-sm font-bold transition-all"
            >
                <LogOut size={16} />
                Sign Out
            </button>
        </div>
    );
};

export default Settings;
