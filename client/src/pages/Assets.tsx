import React, { useState, useEffect } from 'react';
import { Globe, Plus, Download, Search, ChevronDown, Shield, Activity, ExternalLink, Loader2, RefreshCw } from 'lucide-react';

const BACKEND_URL = 'http://localhost:3001';

interface Asset {
    target: string;
    domain: string;
    scansCount: number;
    riskLevel: 'C' | 'H' | 'M' | 'L' | 'I';
}

const severityConfig: Record<string, { label: string; color: string; bg: string; dot: string }> = {
    C: { label: 'Critical', color: 'text-red-400', bg: 'bg-red-500/15', dot: 'bg-red-400' },
    H: { label: 'High', color: 'text-red-400', bg: 'bg-red-500/15', dot: 'bg-red-400' },
    M: { label: 'Medium', color: 'text-amber-400', bg: 'bg-amber-500/15', dot: 'bg-amber-400' },
    L: { label: 'Low', color: 'text-blue-400', bg: 'bg-blue-500/15', dot: 'bg-blue-400' },
    I: { label: 'Info', color: 'text-emerald-400', bg: 'bg-emerald-500/15', dot: 'bg-emerald-400' },
};

const Assets: React.FC = () => {
    const [assets, setAssets] = useState<Asset[]>([]);
    const [loading, setLoading] = useState(true);

    const fetchAssets = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem('accessToken');
            const workspaceId = localStorage.getItem('workspaceId');
            if (!token || !workspaceId) {
                setLoading(false);
                return;
            }

            const res = await fetch(`${BACKEND_URL}/api/workspaces/${workspaceId}/assets`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await res.json();
            setAssets(data || []);
        } catch (err) {
            console.error('Failed to fetch assets', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchAssets(); }, []);

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-black text-white tracking-tight">Assets</h1>
                    <p className="text-sm text-[#6b7280] mt-1">Only targets that already have a saved report (same scope as Reports).</p>
                </div>
                <div className="flex items-center gap-3">
                    <button className="flex items-center gap-2 px-4 py-2 bg-brand hover:bg-red-700 text-white rounded-lg text-sm font-bold transition-all shadow-lg shadow-brand/25">
                        <Plus size={16} />
                        Add Asset
                    </button>
                    <button onClick={fetchAssets} className="p-2 bg-[#0f1418] border border-[#1e262e] text-[#6b7280] hover:text-white rounded-lg transition-colors">
                        <RefreshCw size={16} />
                    </button>
                </div>
            </div>

            <div className="bg-[#0f1418]/60 border border-[#1e262e] rounded-xl overflow-hidden backdrop-blur-md">
                <table className="w-full text-left">
                    <thead className="bg-[#0a0d12] border-b border-[#1e262e]">
                        <tr>
                            <th className="py-3 px-5 text-[10px] text-[#6b7280] uppercase font-bold tracking-widest">Target</th>
                            <th className="py-3 px-5 text-[10px] text-[#6b7280] uppercase font-bold tracking-widest">Risk Level</th>
                            <th className="py-3 px-5 text-[10px] text-[#6b7280] uppercase font-bold tracking-widest">Scans</th>
                            <th className="py-3 px-5 text-[10px] text-[#6b7280] uppercase font-bold tracking-widest text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e262e]/50">
                        {loading ? (
                            <tr>
                                <td colSpan={4} className="py-12 text-center">
                                    <Loader2 size={24} className="text-brand animate-spin mx-auto mb-2" />
                                    <p className="text-[#6b7280] text-sm">Loading assets...</p>
                                </td>
                            </tr>
                        ) : assets.length === 0 ? (
                            <tr>
                                <td colSpan={4} className="py-12 text-center">
                                    <Globe size={32} className="text-[#334155] mx-auto mb-2" />
                                    <p className="text-[#6b7280] text-sm">No assets found in this workspace.</p>
                                </td>
                            </tr>
                        ) : (
                            assets.map((asset, i) => {
                                const sev = severityConfig[asset.riskLevel] || severityConfig.M;
                                return (
                                    <tr key={i} className="hover:bg-[#1e262e]/30 transition-colors group">
                                        <td className="py-3 px-5">
                                            <div className="flex flex-col">
                                                <span className="text-sm font-semibold text-white">{asset.target}</span>
                                                <span className="text-[10px] text-[#64748b] font-mono">{asset.domain}</span>
                                            </div>
                                        </td>
                                        <td className="py-3 px-5">
                                            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold uppercase ${sev.bg} ${sev.color}`}>
                                                <div className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
                                                {sev.label}
                                            </span>
                                        </td>
                                        <td className="py-3 px-5 text-sm text-[#9ca3af]">
                                            {asset.scansCount} scans
                                        </td>
                                        <td className="py-3 px-5 text-right">
                                            <button className="text-[#64748b] hover:text-brand transition-colors">
                                                <ExternalLink size={14} />
                                            </button>
                                        </td>
                                    </tr>
                                );
                            })
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default Assets;
