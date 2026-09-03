
import React, { useState, useRef, useEffect } from 'react';
import {
  Send, Bot, User, Loader2, Sparkles, Target, ShieldAlert,
  CheckCircle2, AlertCircle, Clock, Search, Globe, Brain, Zap,
  Activity, AlertTriangle, Crosshair, ChevronDown, ChevronRight, XCircle
} from 'lucide-react';
import { ChatMessage } from '../types/index';

const BACKEND_URL = 'http://localhost:3001';

// ─── Markdown-lite renderer (bold + line breaks) ──────────────────────────
function renderMarkdown(text: string) {
  const lines = text.split('\n');
  return lines.map((line, i) => {
    // Headings
    if (line.startsWith('### ')) return <h3 key={i} className="text-red-300 font-semibold mt-3 mb-1">{line.slice(4)}</h3>;
    if (line.startsWith('## ')) return <h2 key={i} className="text-red-400 font-bold mt-4 mb-1 text-base">{line.slice(3)}</h2>;
    if (line.startsWith('# ')) return <h1 key={i} className="text-white font-bold mt-4 mb-1 text-lg">{line.slice(2)}</h1>;

    // Bullet points
    if (line.startsWith('- ') || line.startsWith('* ')) {
      return (
        <div key={i} className="flex gap-2 my-0.5 ml-2">
          <span className="text-brand flex-shrink-0 mt-0.5">•</span>
          <span>{boldify(line.slice(2))}</span>
        </div>
      );
    }

    // Numbered list
    const numbered = line.match(/^(\d+)\. (.*)/);
    if (numbered) {
      return (
        <div key={i} className="flex gap-2 my-0.5 ml-2">
          <span className="text-red-300 font-mono flex-shrink-0">{numbered[1]}.</span>
          <span>{boldify(numbered[2])}</span>
        </div>
      );
    }

    if (line.trim() === '') return <div key={i} className="my-1" />;
    return <p key={i} className="my-0.5">{boldify(line)}</p>;
  });
}

function boldify(text: string) {
  const parts = text.split(/\*\*(.*?)\*\*/g);
  return parts.map((part, i) =>
    i % 2 === 1 ? <strong key={i} className="text-white font-semibold">{part}</strong> : part
  );
}

// ─── Phase icon helper ────────────────────────────────────────────────────
function PhaseIcon({ phase, status }: { phase: string; status: string }) {
  const iconClass = status === 'running' ? 'text-red-400 animate-pulse' : 'text-green-400';
  const icons: Record<string, React.ReactElement> = {
    subfinder: <Search size={14} className={iconClass} />,
    ssl_san: <ShieldAlert size={14} className={iconClass} />,
    gau_subs: <Globe size={14} className={iconClass} />,
    httpx: <Globe size={14} className={iconClass} />,
    nmap: <Target size={14} className={iconClass} />,
    ffuf: <Target size={14} className={iconClass} />,
    gau_endpoints: <Globe size={14} className={iconClass} />,
    ai_analysis: <Sparkles size={14} className={iconClass} />,
    start: <CheckCircle2 size={14} className={iconClass} />,
    // Agent phases
    recon: <Search size={14} className={iconClass} />,
    analysis: <Brain size={14} className={iconClass} />,
    exploit: <Crosshair size={14} className={iconClass} />,
    react: <Activity size={14} className={iconClass} />,
    agent: <Brain size={14} className={iconClass} />,
    report: <Sparkles size={14} className={iconClass} />,
    pipeline: <Globe size={14} className={iconClass} />,
    attack_surface: <Crosshair size={14} className={iconClass} />,
    final_analysis: <Brain size={14} className={iconClass} />,
    unified_report: <Sparkles size={14} className={iconClass} />,
  };
  return icons[phase] || <Clock size={14} className={iconClass} />;
}


// ─── Progress Card ────────────────────────────────────────────────────────
interface ProgressEntry {
  phase: string;
  status: string;
  message: string;
  type?: string;
  hypothesis?: string;
  confidence?: string;
  action?: string;
  parameters?: Record<string, unknown>;
  vulnerability?: {
    type: string;
    endpoint: string;
    payload?: string;
    evidence?: string;
    impact?: string;
    severity: string;
  };
  step?: number;
}

function ProgressPanel({ entries }: { entries: ProgressEntry[] }) {
  if (entries.length === 0) return null;

  // Group into recon and agent sections
  const reconEntries = entries.filter(e =>
    !['thought', 'action', 'result', 'vuln_confirmed'].includes(e.type || '') &&
    !['react', 'exploit'].includes(e.phase)
  );
  const agentEntries = entries.filter(e =>
    ['thought', 'action', 'result', 'vuln_confirmed'].includes(e.type || '') ||
    ['react', 'exploit', 'agent', 'analysis'].includes(e.phase)
  );
  const vulns = entries.filter(e => e.type === 'vuln_confirmed');

  return (
    <div className="mt-3 space-y-3 text-xs">
      {/* Recon progress */}
      {reconEntries.length > 0 && (
        <div className="space-y-1.5">
          {reconEntries.map((e, i) => (
            <div key={`r-${i}`} className="flex items-start gap-2">
              <span className="mt-0.5"><PhaseIcon phase={e.phase} status={e.status} /></span>
              <span className={e.status === 'running' ? 'text-red-300' : 'text-slate-400'}>{e.message}</span>
            </div>
          ))}
        </div>
      )}

      {/* Agent Reasoning Timeline */}
      {agentEntries.length > 0 && (
        <div className="mt-4 pt-3 border-t border-slate-700/50">
          <div className="flex items-center gap-2 text-xs text-red-400 font-semibold mb-3 uppercase tracking-wider">
            <Brain size={14} />
            ReAct Agent — Exploitation Loop
          </div>
          <div className="space-y-1.5 pl-2 border-l border-slate-700/40">
            {agentEntries.map((e, i) => (
              <div key={`a-${i}`}>
                <AgentStepLine entry={e} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Confirmed Vulnerabilities Panel */}
      {vulns.length > 0 && (
        <div className="mt-4 pt-3 border-t border-red-500/30">
          <div className="flex items-center gap-2 text-xs text-red-400 font-bold mb-2 uppercase tracking-wider">
            <AlertTriangle size={14} />
            Confirmed Vulnerabilities ({vulns.length})
          </div>
          <div className="space-y-2">
            {vulns.map((v, i) => v.vulnerability && (
              <div key={`v-${i}`}>
                <VulnCard vuln={v.vulnerability} />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Agent Step Line ──────────────────────────────────────────────────────
function AgentStepLine({ entry }: { entry: ProgressEntry }) {
  const [expanded, setExpanded] = useState(false);

  const getIcon = () => {
    switch (entry.type) {
      case 'thought': return <Brain size={12} className="text-amber-400" />;
      case 'action': return <Zap size={12} className="text-red-400" />;
      case 'result': return <Activity size={12} className="text-green-400" />;
      case 'vuln_confirmed': return <AlertTriangle size={12} className="text-red-400" />;
      default: return <PhaseIcon phase={entry.phase} status={entry.status} />;
    }
  };

  const isVuln = entry.type === 'vuln_confirmed';
  const hasDetails = entry.hypothesis || entry.parameters || entry.vulnerability;

  return (
    <div className={`pl-3 py-1 ${isVuln ? 'bg-red-950/20 rounded-lg border border-red-500/20 px-2' : ''}`}>
      <div
        className={`flex items-start gap-2 ${hasDetails ? 'cursor-pointer' : ''}`}
        onClick={() => hasDetails && setExpanded(!expanded)}
      >
        <span className="mt-0.5 flex-shrink-0">{getIcon()}</span>
        {entry.step && (
          <span className="text-slate-600 text-[10px] mt-0.5 flex-shrink-0">#{entry.step}</span>
        )}
        <span className={`flex-1 ${isVuln ? 'text-red-300 font-semibold' :
          entry.type === 'thought' ? 'text-amber-200/80' :
            entry.type === 'action' ? 'text-red-300' :
              entry.type === 'result' ? 'text-green-300' :
                entry.status === 'running' ? 'text-red-300' : 'text-slate-400'
          }`}>
          {entry.message}
        </span>
        {entry.confidence && (
          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 mt-1.5 ${entry.confidence === 'high' ? 'bg-green-400' :
            entry.confidence === 'medium' ? 'bg-yellow-400' : 'bg-red-400'
            }`} />
        )}
        {hasDetails && (
          expanded ? <ChevronDown size={10} className="text-slate-600 mt-1" /> : <ChevronRight size={10} className="text-slate-600 mt-1" />
        )}
      </div>

      {expanded && (
        <div className="ml-5 mt-1 space-y-1 text-[10px]">
          {entry.hypothesis && (
            <p><span className="text-slate-500">Hypothesis:</span> <span className="text-amber-300">{entry.hypothesis}</span></p>
          )}
          {entry.action && entry.type === 'action' && (
            <p><span className="text-slate-500">Tool:</span> <span className="text-red-300 font-mono">{entry.action}</span></p>
          )}
          {entry.parameters && Object.keys(entry.parameters).length > 0 && (
            <pre className="bg-slate-900/50 rounded p-1.5 text-slate-500 overflow-x-auto max-h-16">
              {JSON.stringify(entry.parameters, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Vulnerability Card ───────────────────────────────────────────────────
function VulnCard({ vuln }: { vuln: NonNullable<ProgressEntry['vulnerability']> }) {
  const sevColors: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-red-600 text-white',
    medium: 'bg-yellow-500 text-black',
    low: 'bg-green-500 text-white',
  };

  const renderValue = (val: any) => {
    if (val === null || val === undefined) return 'N/A';
    if (typeof val === 'object') return JSON.stringify(val, null, 1);
    return String(val);
  };

  return (
    <div className="bg-red-950/20 rounded-lg border border-red-500/20 p-2.5">
      <div className="flex items-center gap-2 mb-1">
        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${sevColors[(vuln.severity || '').toLowerCase()] || 'bg-slate-600 text-white'}`}>
          {vuln.severity || 'UNKNOWN'}
        </span>
        <span className="text-red-200 text-xs font-semibold">{vuln.type}</span>
      </div>
      <div className="text-[10px] text-slate-400 space-y-0.5">
        <p>Endpoint: <code className="text-red-300">{renderValue(vuln.endpoint)}</code></p>
        {vuln.payload && <p>Payload: <code className="text-amber-300">{renderValue(vuln.payload)}</code></p>}
        {vuln.evidence && <p>Evidence: <span className="text-green-300 overflow-hidden text-ellipsis block whitespace-pre-wrap">{renderValue(vuln.evidence)}</span></p>}
        {vuln.impact && <p>Impact: {renderValue(vuln.impact)}</p>}
      </div>
    </div>
  );
}

// ─── Message types ────────────────────────────────────────────────────────
interface ScanMessage extends ChatMessage {
  isScanning?: boolean;
  progressEntries?: ProgressEntry[];
  error?: string;
  agentReport?: {
    vulns: Array<{
      type: string;
      endpoint: string;
      payload?: string;
      evidence?: string;
      impact?: string;
      severity: string;
    }>;
    summary: string;
    duration_ms: number;
    report?: {
      markdown?: string;
      findings?: {
        total: number;
        severityDistribution: Record<string, number>;
      };
    };
  };
}

// ─── Main Component ───────────────────────────────────────────────────────
const AIScanner: React.FC = () => {
  const [messages, setMessages] = useState<ScanMessage[]>([
    {
      role: 'assistant',
      content: "👋 Hello! I'm **RedVapt AI**, your intelligent pentesting assistant.\n\nI run a **full security pipeline** — autonomous reconnaissance discovers your target's attack surface, then the exploitation agent tests for vulnerabilities using 7 specialist modules (SQLi, XSS, SSRF, Auth Bypass, IDOR, Command Injection, Path Traversal).\n\nType a domain to start a **full scan**, or just ask me anything about security.",
      timestamp: new Date(),
    }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const activeEventSourceRef = useRef<EventSource | null>(null);

  const handleStopScan = async () => {
    // 1. Instantly kill the frontend loader and SSE connection
    if (activeEventSourceRef.current) {
      activeEventSourceRef.current.close();
      activeEventSourceRef.current = null;
    }
    setIsLoading(false);

    let targetToStop: string | null = null;
    setMessages(prev => prev.map(msg => {
      // Find the active scanning message
      if ((msg as ScanMessage).isScanning) {
        targetToStop = msg.content;
        return { ...msg, isScanning: false, error: '🛑 **Scan forcefully stopped by user.**' };
      }
      return msg;
    }));

    // 2. Call the backend to trigger the AbortController kill switch
    if (targetToStop) {
      const workspaceId = localStorage.getItem('workspaceId') || '1';
      fetch(`${BACKEND_URL}/api/recon/workspaces/${workspaceId}/scan/stop?target=${encodeURIComponent(targetToStop)}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('accessToken')}` }
      }).catch(err => console.error('[StopScan] error:', err));
    }
  };
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Check if input looks like a domain/URL to decide which flow to use
  const looksLikeDomain = (text: string) => {
    const cleaned = text.trim().replace(/^https?:\/\//i, '');
    return /^[\w.-]+\.[a-z]{2,}(\/.*)?$/i.test(cleaned) && !text.includes(' ');
  };

  // ─── Queue-based Recon + Agent Scan ───────────────────────────────
  const runScan = async (target: string) => {
    const cleanTarget = target.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim();

    // User message
    const userMsg: ScanMessage = { role: 'user', content: `🔍 Scan target: **${cleanTarget}**`, timestamp: new Date() };
    // Bot placeholder (we'll update it in-place)
    const botMsg: ScanMessage = {
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      isScanning: true,
      progressEntries: [{ phase: 'start', status: 'running', message: `🚀 Enqueueing scan for **${cleanTarget}**...` }],
    };

    setMessages(prev => [...prev, userMsg, botMsg]);
    setIsLoading(true);

    const updateBot = (updater: (msg: ScanMessage) => ScanMessage) => {
      setMessages(prev => {
        const next = [...prev];
        const idx = next.length - 1;
        if (next[idx] && next[idx].role === 'assistant') {
          next[idx] = updater(next[idx] as ScanMessage);
        }
        return next;
      });
    };

    const token = localStorage.getItem('accessToken') || '';
    const workspaceId = localStorage.getItem('workspaceId') || '';
    const eventSource = new EventSource(`${BACKEND_URL}/api/recon/workspaces/${workspaceId}/scan?target=${encodeURIComponent(cleanTarget)}&token=${token}`);
    activeEventSourceRef.current = eventSource;

    const safeParse = (json: string) => {
      try { return JSON.parse(json); }
      catch (e) { console.error('SSE Parse Error:', e, json); return {}; }
    };

    eventSource.addEventListener('start', (e) => {
      const data = safeParse(e.data);
      updateBot(msg => ({
        ...msg,
        progressEntries: [{ phase: 'start', status: 'done', message: data.message || 'Starting...' }]
      }));
    });

    eventSource.addEventListener('progress', (e) => {
      const data = safeParse(e.data);
      updateBot(msg => ({
        ...msg,
        progressEntries: [...(msg.progressEntries || []), data]
      }));
    });

    // Agent-specific events (thoughts, actions, results)
    eventSource.addEventListener('thought', (e) => {
      const data = safeParse(e.data);
      updateBot(msg => ({
        ...msg,
        progressEntries: [...(msg.progressEntries || []), { ...data, type: 'thought' }]
      }));
    });

    eventSource.addEventListener('action', (e) => {
      const data = safeParse(e.data);
      updateBot(msg => ({
        ...msg,
        progressEntries: [...(msg.progressEntries || []), { ...data, type: 'action' }]
      }));
    });

    eventSource.addEventListener('result', (e) => {
      const data = safeParse(e.data);
      updateBot(msg => ({
        ...msg,
        progressEntries: [...(msg.progressEntries || []), { ...data, type: 'result' }]
      }));
    });

    eventSource.addEventListener('vuln_confirmed', (e) => {
      const data = safeParse(e.data);
      updateBot(msg => ({
        ...msg,
        progressEntries: [...(msg.progressEntries || []), { ...data, type: 'vuln_confirmed' }]
      }));
    });

    eventSource.addEventListener('analysis', (_e) => {
      // Analysis goes to report only
    });

    eventSource.addEventListener('agent_report', (e) => {
      const data = safeParse(e.data);
      updateBot(msg => ({ ...msg, agentReport: data }));
    });

    eventSource.addEventListener('final_analysis', (_e) => {
      // Analysis goes to report only
    });

    eventSource.addEventListener('attack_surface', (e) => {
      const data = safeParse(e.data);
      updateBot(msg => ({
        ...msg,
        progressEntries: [...(msg.progressEntries || []), { ...data, type: 'attack_surface', phase: 'attack_surface', status: 'done' }]
      }));
    });

    eventSource.addEventListener('done', (_e) => {
      updateBot(msg => ({ ...msg, isScanning: false }));
      eventSource.close();
      setIsLoading(false);
    });

    eventSource.addEventListener('error', (e: MessageEvent) => {
      let errMsg = '❌ Scan failed. Is the backend server running?';
      if (e.data) {
        try {
          const data = JSON.parse(e.data);
          errMsg = data.message || errMsg;
        } catch { /* ignored */ }
      }
      updateBot(msg => ({ ...msg, isScanning: false, error: errMsg }));
      eventSource.close();
      setIsLoading(false);
    });

    // Native error (server unreachable)
    eventSource.onerror = () => {
      if (eventSource.readyState === EventSource.CLOSED) return;
      eventSource.close();
      updateBot(msg => ({
        ...msg,
        isScanning: false,
        error: '❌ Cannot connect to the backend server.',
      }));
      setIsLoading(false);
    };
  };

  // ─── Chat Flow ──────────────────────────────────────────────────────
  const runChat = async (message: string) => {
    const userMsg: ScanMessage = { role: 'user', content: message, timestamp: new Date() };
    setMessages(prev => [...prev, userMsg]);


    try {
      const res = await fetch(`${BACKEND_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message }),
      });

      let reply: string;
      if (res.ok) {
        const data = await res.json();
        reply = data.reply;
      } else {
        // Fall back to direct browser call if backend is unavailable
        const { GroqService } = await import('../services/groqService');
        reply = await GroqService.getInstance().chat(message);
      }

      const botMsg: ScanMessage = { role: 'assistant', content: reply, timestamp: new Date() };
      setMessages(prev => [...prev, botMsg]);
    } catch {
      // Fall back to direct browser Groq call
      try {
        const { GroqService } = await import('../services/groqService');
        const reply = await GroqService.getInstance().chat(message);
        setMessages(prev => [...prev, { role: 'assistant', content: reply, timestamp: new Date() }]);
      } catch (err2) {
        setMessages(prev => [...prev, {
          role: 'assistant',
          content: '❌ Error communicating with AI. Please check your API key.',
          timestamp: new Date()
        }]);
      }
    }
  };

  // ─── Form Submit ────────────────────────────────────────────────────
  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    const text = input.trim();
    if (!text || isLoading) return;
    setInput('');
    setIsLoading(true);

    if (looksLikeDomain(text)) {
      await runScan(text);
    } else {
      await runChat(text);
      setIsLoading(false);
    }
  };

  // ─── Render ─────────────────────────────────────────────────────────
  return (
    <div className="pt-24 pb-12 px-6 h-screen flex flex-col max-w-6xl mx-auto">
      {/* Header */}
      <header className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 mb-6 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-brand/15 rounded-xl">
            <Bot className="text-brand" size={24} />
          </div>
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              AI Security Scanner
              <Sparkles size={16} className="text-red-300" />
            </h1>
            <p className="text-slate-500 text-sm">Autonomous Recon • AI Exploitation Agent • 7 Vulnerability Specialists</p>
          </div>
        </div>
        <div className="hidden md:flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1 bg-green-500/10 border border-green-500/20 text-green-500 text-xs rounded-full">
            <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
            Agent Ready
          </div>
        </div>
      </header>

      {/* Chat Area */}
      <div className="flex-1 bg-slate-900/20 border border-slate-800 rounded-3xl overflow-hidden flex flex-col">
        <div className="flex-1 overflow-y-auto p-6 space-y-6 scrollbar-thin scrollbar-thumb-slate-700">
          {messages.map((msg, idx) => {
            const scanMsg = msg as ScanMessage;
            return (
              <div
                key={idx}
                className={`flex gap-4 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {msg.role === 'assistant' && (
                  <div className="w-10 h-10 rounded-xl bg-brand flex items-center justify-center flex-shrink-0 mt-1">
                    {scanMsg.isScanning
                      ? <Loader2 size={20} className="text-white animate-spin" />
                      : <Bot size={20} className="text-white" />
                    }
                  </div>
                )}
                <div className={`max-w-[80%] rounded-2xl p-4 shadow-xl text-sm ${msg.role === 'user'
                  ? 'bg-blue-600 text-white rounded-tr-none'
                  : 'bg-slate-800/80 text-slate-200 border border-slate-700 rounded-tl-none'
                  }`}>
                  {/* Regular content */}
                  {msg.content && (
                    <div className="whitespace-pre-wrap leading-relaxed">
                      {renderMarkdown(msg.content)}
                    </div>
                  )}

                  {/* Scan progress + Agent timeline */}
                  {scanMsg.progressEntries && scanMsg.progressEntries.length > 0 && (
                    <ProgressPanel entries={scanMsg.progressEntries} />
                  )}

                  {/* Agent Report */}
                  {scanMsg.agentReport && (
                    <div className="mt-4 pt-4 border-t border-red-500/30">
                      <div className="flex items-center gap-2 text-xs text-red-400 font-semibold mb-2 uppercase tracking-wider">
                        <Crosshair size={12} />
                        Agent Exploitation Report
                      </div>
                      <p className="text-slate-300 text-xs mb-2">{scanMsg.agentReport.summary}</p>
                      {scanMsg.agentReport.report?.findings && (
                        <div className="flex gap-2 mb-2">
                          {Object.entries(scanMsg.agentReport.report.findings.severityDistribution || {}).map(([sev, count]) => (
                            <div key={sev} className="text-center bg-slate-900/50 rounded px-3 py-1">
                              <div className="text-sm font-bold text-white">{String(count)}</div>
                              <div className="text-[9px] text-slate-500 uppercase">{sev}</div>
                            </div>
                          ))}
                        </div>
                      )}
                      {scanMsg.agentReport.report?.markdown && (
                        <details className="mt-2">
                          <summary className="text-[10px] text-red-400 cursor-pointer hover:text-red-300">
                            View Full Pentest Report
                          </summary>
                          <pre className="mt-2 text-[10px] bg-slate-900 rounded p-3 overflow-x-auto max-h-64 text-slate-400 whitespace-pre-wrap">
                            {String(scanMsg.agentReport.report.markdown)}
                          </pre>
                        </details>
                      )}
                    </div>
                  )}

                  {/* Error */}
                  {scanMsg.error && (
                    <div className="mt-3 p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-300 text-xs">
                      <div className="flex items-center gap-1.5 mb-1 font-semibold">
                        <AlertCircle size={12} />
                        Error
                      </div>
                      {renderMarkdown(scanMsg.error)}
                    </div>
                  )}

                  {/* Timestamp */}
                  <div className={`text-[10px] mt-2 ${msg.role === 'user' ? 'text-blue-200' : 'text-slate-500'}`}>
                    {msg.timestamp.toLocaleTimeString()}
                  </div>
                </div>

                {msg.role === 'user' && (
                  <div className="w-10 h-10 rounded-xl bg-slate-700 flex items-center justify-center flex-shrink-0 mt-1">
                    <User size={20} className="text-white" />
                  </div>
                )}
              </div>
            );
          })}

          {/* Global loading (chat mode) */}
          {isLoading && !messages.some(m => (m as ScanMessage).isScanning) && (
            <div className="flex gap-4 justify-start">
              <div className="w-10 h-10 rounded-xl bg-brand flex items-center justify-center">
                <Loader2 size={20} className="text-white animate-spin" />
              </div>
              <div className="bg-slate-800/80 border border-slate-700 rounded-2xl rounded-tl-none p-4">
                <div className="flex gap-1">
                  {[0, 100, 200].map(d => (
                    <div key={d} className="w-1.5 h-1.5 bg-slate-500 rounded-full animate-bounce" style={{ animationDelay: `${d}ms` }} />
                  ))}
                </div>
              </div>
            </div>
          )}
          <div ref={chatEndRef} />
        </div>

        {/* Stop Scan Control */}
        {messages.some(m => (m as ScanMessage).isScanning) && (
          <div className="flex justify-center -mb-5 relative z-10 pt-2">
            <button
              onClick={handleStopScan}
              className="flex items-center gap-2 bg-red-600 hover:bg-red-500 text-white px-6 py-2 rounded-full font-bold text-sm transition-all shadow-[0_0_15px_rgba(220,38,38,0.5)] active:scale-95 border border-red-400 cursor-pointer hover:shadow-[0_0_25px_rgba(220,38,38,0.7)]"
            >
              <XCircle size={18} /> STOP ACTIVE SCAN
            </button>
          </div>
        )}

        {/* Input Area */}
        <div className="p-6 bg-slate-950/40 border-t border-slate-800">
          <form onSubmit={handleSend} className="relative group">
            <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-red-400 transition-colors">
              <Target size={20} />
            </div>
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Enter a domain to scan (e.g., example.com) or ask a security question..."
              className="w-full bg-slate-900 border border-slate-800 rounded-2xl py-4 pl-12 pr-16 focus:outline-none focus:ring-2 focus:ring-brand/40 transition-all text-slate-200 placeholder:text-slate-600"
            />
            <button
              type="submit"
              disabled={isLoading || !input.trim()}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-3 bg-brand hover:bg-red-700 disabled:bg-slate-800 disabled:text-slate-600 text-white rounded-xl shadow-lg shadow-brand/25 transition-all active:scale-95"
            >
              <Send size={20} />
            </button>
          </form>
          <div className="flex gap-4 mt-4 overflow-x-auto pb-2 scrollbar-none">
            {[
              { label: '🔍 Scan example.com', value: 'example.com' },
              { label: '🔍 Scan hackerone.com', value: 'hackerone.com' },
              { label: '💬 Explain SQL injection', value: 'Explain SQL injection vulnerabilities and how to exploit them safely in a pentest' },
              { label: '💬 OWASP Top 10', value: 'What are the OWASP Top 10 vulnerabilities for 2023?' },
            ].map(q => (
              <button
                key={q.label}
                onClick={() => setInput(q.value)}
                className="whitespace-nowrap px-4 py-1.5 bg-slate-900/60 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-white rounded-full text-xs transition-colors"
              >
                {q.label}
              </button>
            ))}
          </div>
          <p className="text-[10px] text-slate-600 mt-2 text-center">
            ⚡ Type a domain to trigger a full security assessment pipeline.
          </p>
        </div>
      </div>
    </div>
  );
};

export default AIScanner;
