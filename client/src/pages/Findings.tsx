import React, { useState, useEffect } from 'react';
import { ShieldAlert, ChevronDown, ChevronRight, Loader2, Search, ExternalLink, AlertTriangle, Info, Shield, Bug, RefreshCw } from 'lucide-react';

const BACKEND_URL = 'http://localhost:3001';

interface Finding {
    title: string;
    target: string;
    status: string;
    riskLevel: 'C' | 'H' | 'M' | 'L' | 'I';
    description: string;
    evidence: string;
    endpoint: string;
    remediation: string;
    payload: string;
    cvss: number | null;
    scanDate: string;
}

const severityConfig: Record<string, { label: string; color: string; bg: string; border: string; dot: string }> = {
    C: { label: 'Critical', color: 'text-red-400', bg: 'bg-red-500/15', border: 'border-red-500/30', dot: 'bg-red-400' },
    H: { label: 'High', color: 'text-red-400', bg: 'bg-red-500/15', border: 'border-red-500/30', dot: 'bg-red-400' },
    M: { label: 'Medium', color: 'text-amber-400', bg: 'bg-amber-500/15', border: 'border-amber-500/30', dot: 'bg-amber-400' },
    L: { label: 'Low', color: 'text-blue-400', bg: 'bg-blue-500/15', border: 'border-blue-500/30', dot: 'bg-blue-400' },
    I: { label: 'Info', color: 'text-emerald-400', bg: 'bg-emerald-500/15', border: 'border-emerald-500/30', dot: 'bg-emerald-400' },
};

const FindingRow: React.FC<{ finding: Finding }> = ({ finding }) => {
    const [expanded, setExpanded] = useState(false);
    const sev = severityConfig[finding.riskLevel] || severityConfig.I;

    return (
        <>
            <tr
                className="hover:bg-[#1e262e]/30 transition-colors cursor-pointer group"
                onClick={() => setExpanded(!expanded)}
            >
                <td className="py-3 px-5">
                    <button className="text-[#6b7280] group-hover:text-white transition-colors">
                        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </button>
                </td>
                <td className="py-3 px-5">
                    <div className="flex items-center gap-2.5">
                        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${sev.dot}`} />
                        <span className="text-sm font-semibold text-white">{finding.title}</span>
                    </div>
                </td>
                <td className="py-3 px-5">
                    <span className="text-sm text-[#9ca3af] font-mono text-xs">{finding.target}</span>
                </td>
                <td className="py-3 px-5">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase ${sev.bg} ${sev.color} ${sev.border} border`}>
                        {sev.label}
                    </span>
                </td>
                <td className="py-3 px-5">
                    <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider ${finding.status === 'Open' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                            finding.status === 'Fixed' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                                'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                        }`}>
                        {finding.status}
                    </span>
                </td>
            </tr>

            {/* Expandable Detail Panel */}
            {expanded && (
                <tr>
                    <td colSpan={5} className="px-5 pb-4">
                        <div className="bg-[#0a0d12] border border-[#1e262e] rounded-xl p-5 ml-8 space-y-4">
                            {finding.endpoint && (
                                <div>
                                    <h4 className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider mb-1">Affected Endpoint</h4>
                                    <code className="text-xs text-red-400 bg-[#0f1418] px-2 py-1 rounded block break-all">{finding.endpoint}</code>
                                </div>
                            )}
                            {finding.description && (
                                <div>
                                    <h4 className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider mb-1">Description</h4>
                                    <p className="text-sm text-[#9ca3af] leading-relaxed">{finding.description}</p>
                                </div>
                            )}
                            {finding.evidence && (
                                <div>
                                    <h4 className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider mb-1">Evidence</h4>
                                    <pre className="text-xs text-amber-300 bg-[#0f1418] px-3 py-2 rounded-lg overflow-x-auto whitespace-pre-wrap max-h-32">{finding.evidence}</pre>
                                </div>
                            )}
                            {finding.payload && (
                                <div>
                                    <h4 className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider mb-1">Payload</h4>
                                    <code className="text-xs text-red-300 bg-[#0f1418] px-2 py-1 rounded block break-all">{finding.payload}</code>
                                </div>
                            )}
                            {finding.remediation && (
                                <div>
                                    <h4 className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider mb-1">Remediation</h4>
                                    <p className="text-sm text-emerald-300/80 leading-relaxed">{finding.remediation}</p>
                                </div>
                            )}
                            {finding.scanDate && (
                                <div className="text-[11px] text-[#64748b] pt-2 border-t border-[#1e262e]">
                                    Discovered: {new Date(finding.scanDate).toLocaleString()}
                                </div>
                            )}
                        </div>
                    </td>
                </tr>
            )}
        </>
    );
};

const Findings: React.FC = () => {
    const [findings, setFindings] = useState<Finding[]>([]);
    const [loading, setLoading] = useState(true);
    const [activeFilter, setActiveFilter] = useState<string>('all');
    const [searchTerm, setSearchTerm] = useState('');

    const fetchFindings = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem('accessToken');
            const workspaceId = localStorage.getItem('workspaceId');
            if (!token || !workspaceId) {
                setLoading(false);
                return;
            }

            const res = await fetch(`${BACKEND_URL}/api/workspaces/${workspaceId}/findings`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await res.json();
            setFindings(data || []);
        } catch (err) {
            console.error('Failed to fetch findings', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchFindings(); }, []);

    const filtered = findings.filter(f => {
        const matchFilter = activeFilter === 'all' || f.riskLevel === activeFilter;
        const matchSearch = searchTerm === '' ||
            f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
            f.target.toLowerCase().includes(searchTerm.toLowerCase());
        return matchFilter && matchSearch;
    });

    const counts: Record<string, number> = {
        all: findings.length,
        C: findings.filter(f => f.riskLevel === 'C').length,
        H: findings.filter(f => f.riskLevel === 'H').length,
        M: findings.filter(f => f.riskLevel === 'M').length,
        L: findings.filter(f => f.riskLevel === 'L').length,
        I: findings.filter(f => f.riskLevel === 'I').length,
    };

    const filterTabs = [
        { key: 'all', label: 'All', color: 'text-white' },
        { key: 'C', label: 'Critical', color: 'text-red-400' },
        { key: 'H', label: 'High', color: 'text-red-400' },
        { key: 'M', label: 'Medium', color: 'text-amber-400' },
        { key: 'L', label: 'Low', color: 'text-blue-400' },
        { key: 'I', label: 'Info', color: 'text-emerald-400' },
    ];

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-black text-white tracking-tight">Findings</h1>
                    <p className="text-sm text-[#6b7280] mt-1">Vulnerabilities discovered across your scanned targets.</p>
                </div>
                <button onClick={fetchFindings} className="flex items-center gap-2 px-4 py-2 bg-[#1e262e] hover:bg-[#334155] text-[#9ca3af] hover:text-white rounded-lg text-sm font-medium transition-all border border-[#334155]">
                    <RefreshCw size={14} />
                    Refresh
                </button>
            </div>

            {/* Severity summary */}
            <div className="grid grid-cols-3 lg:grid-cols-6 gap-3">
                {filterTabs.map(tab => (
                    <button
                        key={tab.key}
                        onClick={() => setActiveFilter(tab.key)}
                        className={`py-3 px-4 rounded-xl text-center transition-all border ${activeFilter === tab.key
                                ? 'bg-brand/15 border-brand/40 ring-1 ring-brand/30'
                                : 'bg-[#0f1418]/60 border-[#1e262e] hover:border-[#334155]'
                            }`}
                    >
                        <p className={`text-xl font-black ${tab.color}`}>{counts[tab.key]}</p>
                        <p className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider mt-1">{tab.label}</p>
                    </button>
                ))}
            </div>

            {/* Search */}
            <div className="relative">
                <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6b7280]" />
                <input
                    type="text"
                    placeholder="Search findings by title or target..."
                    value={searchTerm}
                    onChange={e => setSearchTerm(e.target.value)}
                    className="w-full bg-[#0f1418]/60 border border-[#1e262e] rounded-lg py-2.5 pl-10 pr-4 text-sm text-white placeholder:text-[#64748b] focus:outline-none focus:ring-2 focus:ring-brand/30 focus:border-brand/50 transition-all"
                />
            </div>

            {/* Table */}
            <div className="bg-[#0f1418]/60 border border-[#1e262e] rounded-xl overflow-hidden">
                <table className="w-full text-left">
                    <thead className="border-b border-[#1e262e]">
                        <tr>
                            <th className="py-3 px-5 w-10"></th>
                            <th className="py-3 px-5 text-[10px] text-[#6b7280] uppercase font-bold tracking-wider">Finding ({filtered.length})</th>
                            <th className="py-3 px-5 text-[10px] text-[#6b7280] uppercase font-bold tracking-wider">Target</th>
                            <th className="py-3 px-5 text-[10px] text-[#6b7280] uppercase font-bold tracking-wider w-28">Severity</th>
                            <th className="py-3 px-5 text-[10px] text-[#6b7280] uppercase font-bold tracking-wider w-24">Status</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e262e]/50">
                        {loading ? (
                            <tr>
                                <td colSpan={5} className="py-12 text-center">
                                    <Loader2 size={24} className="text-brand animate-spin mx-auto mb-2" />
                                    <p className="text-[#6b7280] text-sm">Loading findings...</p>
                                </td>
                            </tr>
                        ) : filtered.length === 0 ? (
                            <tr>
                                <td colSpan={5} className="py-12 text-center">
                                    <ShieldAlert size={32} className="text-[#334155] mx-auto mb-2" />
                                    <p className="text-[#6b7280] text-sm">
                                        {findings.length === 0 ? 'No vulnerabilities found yet. Run a scan first.' : 'No findings match this filter.'}
                                    </p>
                                </td>
                            </tr>
                        ) : (
                            filtered.map((finding, i) => (
                                <FindingRow key={i} finding={finding} />
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default Findings;
