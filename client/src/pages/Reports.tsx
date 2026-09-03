import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileText, Download, Eye, Calendar, ShieldCheck, Loader2, AlertCircle, RefreshCw, BarChart3, AlertTriangle, TrendingUp, Trash2 } from 'lucide-react';

const BACKEND_URL = 'http://localhost:3001';

interface ReportSummary {
  id: string;
  target: string;
  scanType: string;
  date: string;
  stats: {
    subdomains: number;
    liveHosts: number;
    services: number;
    endpoints: number;
    jsFiles: number;
    jsSecrets: number;
    parameters: number;
  };
  highSeverityCount: number;
}

const ReportCard: React.FC<{ report: ReportSummary, onDelete: (id: string) => void, onNeedAuth: () => void }> = ({ report, onDelete, onNeedAuth }) => {
  const d = new Date(report.date);
  const dateStr = d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  const timeStr = d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  const score = Math.max(0, 100 - (report.highSeverityCount * 8));

  const handleView = () => {
    const token = localStorage.getItem('accessToken');
    const workspaceId = localStorage.getItem('workspaceId');
    if (!token || !workspaceId) return onNeedAuth();
    window.open(`${BACKEND_URL}/api/reports/workspaces/${workspaceId}/reports/${report.id}/view?token=${token}`, '_blank');
  };

  const handleDownload = () => {
    const token = localStorage.getItem('accessToken');
    const workspaceId = localStorage.getItem('workspaceId');
    if (!token || !workspaceId) return onNeedAuth();
    const a = document.createElement('a');
    a.href = `${BACKEND_URL}/api/reports/workspaces/${workspaceId}/reports/${report.id}/download?token=${token}`;
    a.download = `RedVapt_Report_${report.target}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };
  const handleDelete = async () => {
    if (!window.confirm(`Are you sure you want to delete the report for ${report.target}? This action cannot be undone.`)) return;
    
    const token = localStorage.getItem('accessToken');
    const workspaceId = localStorage.getItem('workspaceId');
    if (!token || !workspaceId) return onNeedAuth();

    try {
      const res = await fetch(`${BACKEND_URL}/api/reports/workspaces/${workspaceId}/reports/${report.id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (!res.ok) throw new Error('Failed to delete report');
      
      onDelete(report.id);
    } catch (err: any) {
      alert(err.message || 'Error deleting report');
    }
  };

  return (
    <div className="bg-[#0f1418]/60 border border-[#1e262e] rounded-xl p-5 hover:border-brand/40 transition-all group">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-4 flex-1 min-w-0">
          <div className="p-3 bg-brand/10 rounded-xl text-brand flex-shrink-0">
            <FileText size={24} />
          </div>
          <div className="min-w-0 flex-1">
            <h3 className="text-base font-bold text-white truncate">{report.target}</h3>
            <div className="flex flex-wrap items-center gap-3 mt-1.5 text-xs">
              <span className="flex items-center gap-1 text-[#6b7280]">
                <Calendar size={12} /> {dateStr} at {timeStr}
              </span>
              <span className="px-2 py-0.5 bg-brand/15 text-brand rounded font-bold uppercase tracking-wider text-[10px]">
                {report.scanType}
              </span>
              {report.highSeverityCount > 0 && (
                <span className="px-2 py-0.5 bg-red-500/15 text-red-400 rounded font-bold text-[10px]">
                  {report.highSeverityCount} Critical
                </span>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-4 mt-3 text-xs text-[#6b7280]">
              <span>{report.stats.subdomains} subdomains</span>
              <span>{report.stats.liveHosts} live hosts</span>
              <span>{report.stats.endpoints} endpoints</span>
              <span>{report.stats.jsFiles} JS files</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-shrink-0">
          {/* Security Score */}
          <div className="hidden lg:flex flex-col items-center gap-1 mr-2">
            <div className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider">Score</div>
            <div className={`text-lg font-black ${score >= 80 ? 'text-emerald-400' : score >= 50 ? 'text-amber-400' : 'text-red-400'}`}>
              {score}
            </div>
          </div>
          <button
            onClick={handleView}
            className="p-2.5 bg-[#1e262e] hover:bg-[#334155] text-[#9ca3af] hover:text-white rounded-lg transition-all"
            title="View Report"
          >
            <Eye size={18} />
          </button>
          <button
            onClick={handleDownload}
            className="p-2.5 bg-brand hover:bg-red-700 text-white rounded-lg transition-all shadow-lg shadow-brand/25"
            title="Download Report"
          >
            <Download size={18} />
          </button>
          <button
            onClick={handleDelete}
            className="p-2.5 bg-[#1e262e] hover:bg-red-500/20 text-[#9ca3af] hover:text-red-400 rounded-lg transition-all"
            title="Delete Report"
          >
            <Trash2 size={18} />
          </button>
        </div>
      </div>
    </div>
  );
};

const Reports: React.FC = () => {
  const navigate = useNavigate();
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const goLogin = () => {
    navigate('/login');
  };

  const fetchReports = async () => {
    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem('accessToken');
      const workspaceId = localStorage.getItem('workspaceId');
      if (!token || !workspaceId) {
        goLogin();
        throw new Error('Sign in to view reports.');
      }

      const res = await fetch(`${BACKEND_URL}/api/reports/workspaces/${workspaceId}/reports`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!res.ok) {
        if (res.status === 401) {
          goLogin();
          throw new Error('Sign in to view reports.');
        }
        throw new Error('Failed to fetch reports');
      }

      const data = await res.json();
      setReports(data.reports || []);
    } catch (err: any) {
      setError(err.message || 'Failed to connect to backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchReports(); }, []);

  const totalReports = reports.length;
  const totalHighSeverity = reports.reduce((sum, r) => sum + (r.highSeverityCount || 0), 0);
  const avgScore = totalReports > 0
    ? Math.round(reports.reduce((sum, r) => sum + Math.max(0, 100 - ((r.highSeverityCount || 0) * 8)), 0) / totalReports)
    : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight">Security Reports</h1>
          <p className="text-sm text-[#6b7280] mt-1">View and download penetration testing reports for your workspace.</p>
        </div>
        <button
          onClick={fetchReports}
          className="flex items-center gap-2 px-4 py-2 bg-[#1e262e] hover:bg-[#334155] text-[#9ca3af] hover:text-white rounded-lg text-sm font-medium transition-all border border-[#334155]"
        >
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0f1418]/60 border border-[#1e262e] rounded-xl p-5">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 bg-brand/10 rounded-lg"><FileText size={16} className="text-brand" /></div>
            <span className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider">Total Reports</span>
          </div>
          <p className="text-3xl font-black text-white">{totalReports}</p>
        </div>
        <div className="bg-[#0f1418]/60 border border-[#1e262e] rounded-xl p-5">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 bg-red-500/10 rounded-lg"><AlertTriangle size={16} className="text-red-400" /></div>
            <span className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider">High Severity</span>
          </div>
          <p className="text-3xl font-black text-red-400">{totalHighSeverity}</p>
        </div>
        <div className="bg-[#0f1418]/60 border border-[#1e262e] rounded-xl p-5">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 bg-emerald-500/10 rounded-lg"><ShieldCheck size={16} className="text-emerald-400" /></div>
            <span className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider">Avg Score</span>
          </div>
          <p className={`text-3xl font-black ${avgScore >= 80 ? 'text-emerald-400' : avgScore >= 50 ? 'text-amber-400' : 'text-red-400'}`}>
            {totalReports > 0 ? `${avgScore}%` : '—'}
          </p>
        </div>
        <div className="bg-[#0f1418]/60 border border-[#1e262e] rounded-xl p-5">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 bg-brand/10 rounded-lg"><BarChart3 size={16} className="text-red-400" /></div>
            <span className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider">Scans Done</span>
          </div>
          <p className="text-3xl font-black text-red-400">{totalReports}</p>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-16">
          <Loader2 size={28} className="text-brand animate-spin" />
          <span className="ml-3 text-[#6b7280]">Loading reports...</span>
        </div>
      )}

      {/* Error */}
      {error && !loading && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-6 text-center">
          <AlertCircle size={28} className="text-red-400 mx-auto mb-2" />
          <p className="text-red-300 font-semibold text-sm">{error}</p>
          <button onClick={fetchReports} className="mt-3 px-4 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-300 rounded-lg text-xs transition-colors">
            Retry
          </button>
        </div>
      )}

      {/* Empty */}
      {!loading && !error && reports.length === 0 && (
        <div className="bg-[#0f1418]/60 border border-[#1e262e] rounded-xl p-12 text-center">
          <FileText size={40} className="text-[#334155] mx-auto mb-3" />
          <h3 className="text-lg font-bold text-[#9ca3af] mb-2">No reports yet</h3>
          <p className="text-[#6b7280] text-sm max-w-md mx-auto">
            Reports are generated after completing scans. Go to <a href="#/workspace/scans" className="text-brand font-semibold hover:underline">New Scan</a> to start.
          </p>
        </div>
      )}

      {/* Report List */}
      {!loading && !error && reports.length > 0 && (
        <div className="space-y-3">
          {reports.map((report) => (
            <ReportCard
              key={report.id}
              report={report}
              onDelete={(id) => setReports(prev => prev.filter(r => r.id !== id))}
              onNeedAuth={goLogin}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export default Reports;
