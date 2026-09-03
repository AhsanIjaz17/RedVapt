import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Activity,
    ShieldAlert,
    Globe,
    Zap,
    Loader2,
    FileText,
    Clock,
    Shield,
    Cpu,
    ArrowRight,
    Radio,
    RefreshCw,
    AlertTriangle,
    Crosshair,
    ChevronRight,
} from 'lucide-react';

const BACKEND_URL = 'http://localhost:3001';

type SeverityBreakdown = {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
};

type RecentReport = {
    id: string;
    target: string;
    scanType?: string;
    date: string;
    highSeverityCount: number;
    totalVulnerabilities?: number;
};

type Stats = {
    activeScans?: number;
    addedAssets?: number;
    highSeverityCount?: number;
    totalReports?: number;
    severityBreakdown?: SeverityBreakdown;
    recentReports?: RecentReport[];
};

const ACCENT_STYLES = {
    red: {
        border: 'border-red-500/20 hover:border-red-500/35',
        glow: 'from-red-600/12 via-transparent to-transparent',
        icon: 'bg-red-500/15 text-red-400 ring-red-500/25',
    },
    emerald: {
        border: 'border-emerald-500/20 hover:border-emerald-500/35',
        glow: 'from-emerald-600/12 via-transparent to-transparent',
        icon: 'bg-emerald-500/15 text-emerald-400 ring-emerald-500/25',
    },
    amber: {
        border: 'border-amber-500/20 hover:border-amber-500/35',
        glow: 'from-amber-600/12 via-transparent to-transparent',
        icon: 'bg-amber-500/15 text-amber-400 ring-amber-500/25',
    },
    slate: {
        border: 'border-zinc-700/50 hover:border-zinc-600/70',
        glow: 'from-zinc-500/8 via-transparent to-transparent',
        icon: 'bg-zinc-800/90 text-zinc-300 ring-zinc-700/60',
    },
} as const;

function KpiCard({
    label,
    value,
    hint,
    icon: Icon,
    accent,
    loading,
}: {
    label: string;
    value: string | number;
    hint: string;
    icon: React.ElementType;
    accent: keyof typeof ACCENT_STYLES;
    loading?: boolean;
}) {
    const s = ACCENT_STYLES[accent];
    return (
        <div
            className={`group relative overflow-hidden rounded-2xl border ${s.border} bg-zinc-900/55 p-5 backdrop-blur-sm transition-all duration-300`}
        >
            <div className={`pointer-events-none absolute inset-0 bg-gradient-to-br ${s.glow}`} />
            <div className="relative flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-zinc-500">{label}</p>
                    {loading ? (
                        <div className="mt-3 h-10 w-20 animate-pulse rounded-lg bg-zinc-800/80" />
                    ) : (
                        <p className="mt-2 font-display text-4xl font-bold tabular-nums tracking-tight text-white">
                            {value}
                        </p>
                    )}
                    <p className="mt-1.5 text-sm text-zinc-500">{hint}</p>
                </div>
                <div className={`shrink-0 rounded-xl p-3 ring-1 ${s.icon}`}>
                    <Icon size={22} strokeWidth={2} />
                </div>
            </div>
        </div>
    );
}

function SeverityBar({
    label,
    count,
    color,
    max,
}: {
    label: string;
    count: number;
    color: string;
    max: number;
}) {
    const pct = max > 0 ? Math.round((count / max) * 100) : 0;
    return (
        <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
                <span className="font-medium text-zinc-400">{label}</span>
                <span className="font-mono font-semibold tabular-nums text-zinc-300">{count}</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-zinc-800/80">
                <div
                    className={`h-full rounded-full transition-all duration-500 ${color}`}
                    style={{ width: `${Math.max(count > 0 ? 8 : 0, pct)}%` }}
                />
            </div>
        </div>
    );
}

function formatReportDate(iso: string) {
    try {
        return new Date(iso).toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
        });
    } catch {
        return '—';
    }
}

const WorkspaceDashboard: React.FC = () => {
    const navigate = useNavigate();
    const [stats, setStats] = useState<Stats | null>(null);
    const [loading, setLoading] = useState(true);
    const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

    const fetchStats = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem('accessToken');
            const workspaceId = localStorage.getItem('workspaceId');
            if (!token || !workspaceId) {
                setLoading(false);
                return;
            }

            const res = await fetch(`${BACKEND_URL}/api/workspaces/${workspaceId}/stats`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
            const data = await res.json();
            setStats(data);
            setLastUpdated(new Date());
        } catch (err) {
            console.error('Failed to fetch stats', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchStats();
    }, []);

    const breakdown = stats?.severityBreakdown;
    const totalVulns = breakdown
        ? breakdown.critical + breakdown.high + breakdown.medium + breakdown.low + breakdown.info
        : 0;
    const maxSeverity = breakdown
        ? Math.max(breakdown.critical, breakdown.high, breakdown.medium, breakdown.low, breakdown.info, 1)
        : 1;

    const riskTone = useMemo(() => {
        const h = stats?.highSeverityCount ?? 0;
        if (h >= 5) return { label: 'Elevated exposure', color: 'text-red-400', bar: 'bg-red-500', ring: 'ring-red-500/30' };
        if (h >= 1) return { label: 'Review recommended', color: 'text-amber-400', bar: 'bg-amber-500', ring: 'ring-amber-500/30' };
        return { label: 'Within baseline', color: 'text-emerald-400', bar: 'bg-emerald-500', ring: 'ring-emerald-500/30' };
    }, [stats]);

    const riskPct = Math.min(100, ((stats?.highSeverityCount ?? 0) / Math.max(5, stats?.highSeverityCount ?? 1)) * 100);

    return (
        <div className="space-y-8 pb-10 text-zinc-200">
            {/* Header */}
            <div className="relative overflow-hidden rounded-2xl border border-zinc-800/80 bg-gradient-to-br from-zinc-900/90 via-zinc-950 to-zinc-950 px-6 py-7 sm:px-8">
                <div className="pointer-events-none absolute -right-20 -top-20 h-56 w-56 rounded-full bg-red-600/10 blur-3xl" />
                <div className="pointer-events-none absolute -bottom-16 left-1/3 h-40 w-40 rounded-full bg-zinc-600/5 blur-3xl" />
                <div className="relative flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
                    <div>
                        <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-red-500/20 bg-red-500/5 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-red-400/90">
                            <Radio size={12} strokeWidth={2.5} className="text-red-500" />
                            Pentest workspace
                        </div>
                        <h1 className="font-display text-3xl font-bold tracking-tight text-white sm:text-4xl">
                            Engagement overview
                        </h1>
                        <p className="mt-2 max-w-2xl text-sm leading-relaxed text-zinc-400 sm:text-base">
                            Metrics are computed from penetration test reports saved for this workspace — each
                            high-severity count is an individual critical or high vulnerability in those reports.
                        </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-3">
                        <button
                            type="button"
                            onClick={fetchStats}
                            disabled={loading}
                            className="inline-flex items-center gap-2 rounded-lg border border-zinc-700/80 bg-zinc-900/60 px-3.5 py-2 text-xs font-semibold text-zinc-300 transition hover:border-zinc-600 hover:bg-zinc-800 hover:text-white disabled:opacity-50"
                        >
                            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
                            Refresh
                        </button>
                        <div className="flex items-center gap-2 rounded-lg border border-zinc-800/80 bg-zinc-950/50 px-3.5 py-2 text-xs text-zinc-500">
                            <Clock size={14} />
                            <span className="font-mono">
                                {lastUpdated ? lastUpdated.toLocaleString() : '—'}
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            {/* KPI row */}
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <KpiCard
                    label="Active scans"
                    value={stats?.activeScans ?? 0}
                    hint="Currently running in AI Scanner"
                    icon={Activity}
                    accent="slate"
                    loading={loading}
                />
                <KpiCard
                    label="High-severity vulns"
                    value={stats?.highSeverityCount ?? 0}
                    hint="Critical + high findings in reports"
                    icon={ShieldAlert}
                    accent="red"
                    loading={loading}
                />
                <KpiCard
                    label="Targets assessed"
                    value={stats?.addedAssets ?? 0}
                    hint="Distinct targets with saved reports"
                    icon={Globe}
                    accent="emerald"
                    loading={loading}
                />
                <KpiCard
                    label="Reports"
                    value={stats?.totalReports ?? 0}
                    hint="Saved penetration test reports"
                    icon={FileText}
                    accent="amber"
                    loading={loading}
                />
            </div>

            <div className="grid gap-6 lg:grid-cols-3">
                {/* Left column */}
                <section className="space-y-6 lg:col-span-2">
                    {/* Exposure + severity */}
                    <div className="rounded-2xl border border-zinc-800/80 bg-zinc-900/40 p-6 backdrop-blur-sm">
                        <div className="mb-6 flex items-center justify-between">
                            <h2 className="text-xs font-bold uppercase tracking-[0.16em] text-zinc-400">
                                Risk posture
                            </h2>
                            {loading && <Loader2 size={18} className="animate-spin text-zinc-500" />}
                        </div>
                        <div className="grid gap-8 md:grid-cols-2">
                            <div>
                                <p className="text-sm text-zinc-500">Exposure level</p>
                                <p className={`mt-1 font-display text-2xl font-bold ${riskTone.color}`}>
                                    {riskTone.label}
                                </p>
                                <p className="mt-3 text-sm leading-relaxed text-zinc-500">
                                    {totalVulns} confirmed vulnerabilities across{' '}
                                    <span className="font-mono text-zinc-400">{stats?.totalReports ?? 0}</span>{' '}
                                    report{(stats?.totalReports ?? 0) === 1 ? '' : 's'}.
                                </p>
                                <div className="mt-5">
                                    <div className="mb-2 flex justify-between text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
                                        <span>High / critical load</span>
                                        <span className="font-mono text-zinc-300">{stats?.highSeverityCount ?? 0}</span>
                                    </div>
                                    <div className={`h-2 overflow-hidden rounded-full bg-zinc-800 ring-1 ${riskTone.ring}`}>
                                        <div
                                            className={`h-full rounded-full transition-all duration-700 ${riskTone.bar}`}
                                            style={{ width: `${riskPct}%` }}
                                        />
                                    </div>
                                </div>
                            </div>
                            <div className="space-y-3">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                                    Vulnerabilities by severity
                                </p>
                                <SeverityBar label="Critical" count={breakdown?.critical ?? 0} color="bg-red-600" max={maxSeverity} />
                                <SeverityBar label="High" count={breakdown?.high ?? 0} color="bg-orange-500" max={maxSeverity} />
                                <SeverityBar label="Medium" count={breakdown?.medium ?? 0} color="bg-amber-500" max={maxSeverity} />
                                <SeverityBar label="Low" count={breakdown?.low ?? 0} color="bg-blue-500/80" max={maxSeverity} />
                                <SeverityBar label="Info" count={breakdown?.info ?? 0} color="bg-zinc-500" max={maxSeverity} />
                            </div>
                        </div>
                    </div>

                    {/* Recent reports */}
                    <div className="rounded-2xl border border-zinc-800/80 bg-zinc-900/40 backdrop-blur-sm">
                        <div className="flex items-center justify-between border-b border-zinc-800/60 px-6 py-4">
                            <h2 className="text-xs font-bold uppercase tracking-[0.16em] text-zinc-400">
                                Recent reports
                            </h2>
                            <button
                                type="button"
                                onClick={() => navigate('/workspace/reports')}
                                className="inline-flex items-center gap-1 text-xs font-semibold text-red-400 transition hover:text-red-300"
                            >
                                View all
                                <ChevronRight size={14} />
                            </button>
                        </div>
                        <div className="divide-y divide-zinc-800/50">
                            {loading && (
                                <div className="flex items-center justify-center gap-2 px-6 py-12 text-sm text-zinc-500">
                                    <Loader2 size={18} className="animate-spin" />
                                    Loading reports…
                                </div>
                            )}
                            {!loading && (stats?.recentReports?.length ?? 0) === 0 && (
                                <div className="px-6 py-12 text-center">
                                    <FileText className="mx-auto mb-3 text-zinc-600" size={32} />
                                    <p className="text-sm font-medium text-zinc-400">No reports yet</p>
                                    <p className="mt-1 text-xs text-zinc-600">
                                        Run a scan in AI Scanner to generate your first report.
                                    </p>
                                    <button
                                        type="button"
                                        onClick={() => navigate('/workspace/scans')}
                                        className="mt-4 inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-red-500"
                                    >
                                        <Zap size={14} />
                                        Start scan
                                    </button>
                                </div>
                            )}
                            {!loading &&
                                stats?.recentReports?.map((r) => (
                                    <button
                                        key={r.id}
                                        type="button"
                                        onClick={() => navigate('/workspace/reports')}
                                        className="flex w-full items-center gap-4 px-6 py-4 text-left transition hover:bg-zinc-800/30"
                                    >
                                        <div className="rounded-lg bg-zinc-800/80 p-2.5 text-zinc-400">
                                            <Crosshair size={18} />
                                        </div>
                                        <div className="min-w-0 flex-1">
                                            <p className="truncate text-sm font-semibold text-zinc-100">{r.target}</p>
                                            <p className="mt-0.5 text-xs text-zinc-500">
                                                {r.scanType || 'Full scan'} · {formatReportDate(r.date)}
                                            </p>
                                        </div>
                                        <div className="shrink-0 text-right">
                                            {r.highSeverityCount > 0 ? (
                                                <span className="inline-flex items-center gap-1 rounded-md bg-red-500/10 px-2 py-1 text-xs font-bold text-red-400">
                                                    <AlertTriangle size={12} />
                                                    {r.highSeverityCount} high+
                                                </span>
                                            ) : (
                                                <span className="text-xs text-zinc-600">No critical/high</span>
                                            )}
                                        </div>
                                        <ChevronRight size={16} className="shrink-0 text-zinc-600" />
                                    </button>
                                ))}
                        </div>
                    </div>

                    {/* CTA */}
                    <div className="flex flex-col items-start justify-between gap-4 rounded-2xl border border-red-500/15 bg-gradient-to-r from-red-950/40 to-zinc-900/40 px-6 py-5 sm:flex-row sm:items-center">
                        <div>
                            <p className="text-sm font-semibold text-zinc-100">Ready for the next assessment?</p>
                            <p className="mt-1 text-xs text-zinc-500">
                                Launch recon, exploitation, and automated reporting from AI Scanner.
                            </p>
                        </div>
                        <button
                            type="button"
                            onClick={() => navigate('/workspace/scans')}
                            className="inline-flex shrink-0 items-center gap-2 rounded-xl bg-red-600 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-red-900/25 transition hover:bg-red-500"
                        >
                            <Zap size={16} />
                            Open AI Scanner
                            <ArrowRight size={16} />
                        </button>
                    </div>
                </section>

                {/* Right sidebar */}
                <aside className="space-y-5">
                    <h2 className="text-xs font-bold uppercase tracking-[0.16em] text-zinc-400">Engine status</h2>
                    <div className="rounded-2xl border border-zinc-800/80 bg-zinc-900/40 p-5 backdrop-blur-sm">
                        <div className="space-y-5">
                            <div>
                                <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-wider text-zinc-400">
                                    <span>Scanner core</span>
                                    <span className="text-emerald-400">Nominal</span>
                                </div>
                                <div className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-zinc-800">
                                    <div className="h-full w-[92%] rounded-full bg-gradient-to-r from-emerald-600 to-emerald-400" />
                                </div>
                            </div>
                            <div>
                                <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-wider text-zinc-400">
                                    <span>Reasoning tier</span>
                                    <span className="text-red-400">Live</span>
                                </div>
                                <div className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-zinc-800">
                                    <div className="h-full w-full rounded-full bg-gradient-to-r from-red-700 to-red-500" />
                                </div>
                            </div>
                            <div className="flex items-start gap-3 border-t border-zinc-800/70 pt-4">
                                <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-2.5">
                                    <Cpu size={20} className="text-zinc-400" />
                                </div>
                                <div>
                                    <p className="text-sm font-semibold text-zinc-200">Deterministic + LLM assist</p>
                                    <p className="mt-1 text-xs leading-relaxed text-zinc-500">
                                        Tool evidence gates findings before they appear in your reports.
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="rounded-2xl border border-zinc-800/80 bg-zinc-900/40 p-5">
                        <div className="flex gap-3">
                            <Shield className="mt-0.5 shrink-0 text-red-500" size={22} />
                            <div>
                                <p className="text-sm font-bold text-zinc-100">Reporting standard</p>
                                <p className="mt-1.5 text-xs leading-relaxed text-zinc-500">
                                    Only reproducible findings with proof artifacts are promoted to final reports.
                                </p>
                            </div>
                        </div>
                    </div>

                    <div className="rounded-2xl border border-zinc-800/60 bg-zinc-950/50 p-4">
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-600">Quick links</p>
                        <nav className="mt-3 space-y-1">
                            {[
                                { label: 'AI Scanner', path: '/workspace/scans' },
                                { label: 'Reports', path: '/workspace/reports' },
                                { label: 'Findings', path: '/workspace/findings' },
                                { label: 'Attack surface', path: '/workspace/attack-surface' },
                            ].map((link) => (
                                <button
                                    key={link.path}
                                    type="button"
                                    onClick={() => navigate(link.path)}
                                    className="flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm text-zinc-400 transition hover:bg-zinc-800/50 hover:text-zinc-100"
                                >
                                    {link.label}
                                    <ChevronRight size={14} className="text-zinc-600" />
                                </button>
                            ))}
                        </nav>
                    </div>
                </aside>
            </div>
        </div>
    );
};

export default WorkspaceDashboard;
