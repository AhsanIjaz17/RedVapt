import React, { useCallback, useEffect, useState } from 'react';
import { Globe, AlertTriangle, TrendingUp, Loader2, Shield, Target, Lock, RefreshCw, Crosshair, GitBranch } from 'lucide-react';
import AttackTreeDiagram, { type AttackTreeNode, dedupeAttackTreeVulnerabilities } from '../components/attack-tree/AttackTreeDiagram';

const BACKEND_URL = 'http://localhost:3001';

interface GraphNode {
  id: string;
  type: 'entry' | 'asset' | 'vulnerability' | 'impact' | string;
  label: string;
  severity?: string;
  endpoint?: string;
  description?: string;
  mitigation?: string;
  mitreTactic?: string;
  mitreId?: string;
}

interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

interface GraphStats {
  totalNodes: number;
  totalEdges: number;
  criticalPaths: number;
  impactAreas: number;
  severityBreakdown: Record<string, number>;
}

interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: GraphStats;
  attackTree?: AttackTreeNode;
  rootDomain?: string;
}

function extractHost(u: string) {
  try {
    const s = /^https?:/i.test(u) ? u : `https://${u}`;
    return new URL(s).hostname.replace(/^www\./i, '');
  } catch {
    return String(u)
      .replace(/^https?:\/\//i, '')
      .split(/[/?#]/)[0]
      .replace(/^www\./i, '') || u;
  }
}

/** When API omits attackTree (older deployments), approximate tree from legacy nodes/edges. */
function fallbackAttackTree(data: GraphData): AttackTreeNode {
  const byId = new Map(data.nodes.map((n) => [n.id, n]));
  const assets = data.nodes.filter((n) => n.type === 'asset');

  let rootLabel = data.rootDomain;
  if (!rootLabel || rootLabel.toLowerCase().includes('add your domain')) {
    const first = assets[0]?.label;
    rootLabel =
      first?.replace(/^https?:\/\//i, '').split(/[/?#]/)[0] || first || 'Define target in Assets';
  }
  const rootHost = extractHost(String(rootLabel));

  const vulns = data.nodes.filter((n) => n.type === 'vulnerability');

  function impactFor(v: GraphNode): string {
    const direct = data.edges.filter((e) => e.source === v.id || e.target === v.id);
    for (const e of direct) {
      const otherId = e.source === v.id ? e.target : e.source;
      const n = byId.get(otherId);
      if (n?.type === 'impact') return n.label;
    }
    return 'Business consequence from confirmed finding';
  }

  function mitigationFor(v: GraphNode): string {
    if (v.mitigation && v.mitigation.trim()) return v.mitigation.trim();
    return 'Review finding details and apply remediation from your secure SDLC playbook.';
  }

  function branchForVuln(v: GraphNode, idx: number): AttackTreeNode {
    const fullImpact = impactFor(v);
    const mit = mitigationFor(v);
    return {
      id: `fallback-v-${v.id}-${idx}`,
      type: 'vulnerability',
      label: v.label.length > 48 ? `${v.label.slice(0, 46)}…` : v.label,
      fullLabel: v.label,
      severity: (v.severity || 'medium').toLowerCase(),
      endpoint: v.endpoint,
      children: [
        {
          id: `fallback-i-${idx}`,
          type: 'impact',
          label: fullImpact.length > 54 ? `${fullImpact.slice(0, 53)}…` : fullImpact,
          fullLabel: fullImpact,
          severity: (v.severity || 'medium').toLowerCase(),
          children: [
            {
              id: `fallback-m-${idx}`,
              type: 'mitigation',
              label: mit.length > 76 ? `${mit.slice(0, 75)}…` : mit,
              fullLabel: mit,
              children: [],
            },
          ],
        },
      ],
    };
  }

  if (assets.length > 1) {
    const bySurface: AttackTreeNode[] = assets.map((a, aj) => {
      const scoped = vulns
        .filter((v) => data.edges.some((e) => e.source === a.id && e.target === v.id))
        .map((v, k) => branchForVuln(v, aj * 1000 + k));
      return {
        id: `fallback-a-${aj}`,
        type: 'surface',
        label: shortenHost(a.label || `Target ${aj + 1}`),
        fullLabel: a.label,
        subtitle: 'Target',
        children: scoped.length
          ? scoped
          : [
              {
                id: `surf-tip-${aj}`,
                type: 'impact',
                label: 'No findings mapped to this target yet',
                fullLabel:
                  'Scanner findings tied to another URL or awaiting import appear here once this workspace associates them.',
                severity: 'info',
                children: [],
              },
            ],
      };
    });
    return {
      id: 'fb-root-multi',
      type: 'domain',
      label: rootHost,
      fullLabel: rootHost,
      subtitle: 'Domain',
      severity: 'info',
      children: bySurface,
    };
  }

  const vulnBranches = vulns.map((v, i) => branchForVuln(v, i));

  return {
    id: 'fb-root-single',
    type: 'domain',
    label: rootHost,
    fullLabel: rootHost,
    subtitle: 'Domain',
    severity: 'info',
    children:
      vulnBranches.length > 0
        ? vulnBranches
        : [
            {
              id: 'fb-empty-impact',
              type: 'impact',
              label: 'Run a penetration scan',
              fullLabel:
                'No modeled vulnerabilities returned from the workspace yet. Finish a scanner run to populate chains and tailored mitigations.',
              severity: 'info',
              children: [
                {
                  id: 'fb-empty-mit',
                  type: 'mitigation',
                  label:
                    'Match this workspace Assets entry, execute a scan from AI Scanner, and refresh Attack Surface.',
                  fullLabel:
                    'Align the Assets domain/host with scanning scope, capture findings, then refresh this page.',
                  children: [],
                },
              ],
            },
          ],
  };
}

function shortenHost(u: string) {
  const h = extractHost(u);
  const s = u.length > 44 ? `${h.slice(0, 41)}…` : h || u.slice(0, 44);
  return s.length > 44 ? `${s.slice(0, 43)}…` : s;
}

function chunkArray<T>(arr: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

const MAX_VULNS_PER_TREE = 12;

/** One diagram per Asset (surface row). Oversized single-target workspaces are split into readable batches. */
function splitTreesForAssets(fullRoot: AttackTreeNode): { key: string; heading: string; tree: AttackTreeNode }[] {
  const domainLabel = fullRoot.fullLabel || fullRoot.label;
  const children = [...(fullRoot.children ?? [])];

  if (children.length === 0) {
    return [{ key: fullRoot.id, heading: `${domainLabel} (workspace)`, tree: fullRoot }];
  }

  if (children.every((c) => c.type === 'surface')) {
    return children.map((surf) => {
      const clonedSurf = JSON.parse(JSON.stringify(surf)) as AttackTreeNode;
      return {
        key: `${fullRoot.id}__asset__${surf.id}`,
        heading: `${domainLabel} → ${surf.fullLabel || surf.label}`,
        tree: {
          ...JSON.parse(JSON.stringify(fullRoot)),
          id: `${fullRoot.id}-only-${surf.id}`,
          subtitle: fullRoot.subtitle,
          children: [clonedSurf],
        },
      };
    });
  }

  if (children.length > MAX_VULNS_PER_TREE) {
    const parts = chunkArray(children, MAX_VULNS_PER_TREE);
    return parts.map((part, i) => ({
      key: `${fullRoot.id}-batch-${i}`,
      heading: `${domainLabel} · findings batch ${i + 1} of ${parts.length}`,
      tree: {
        ...JSON.parse(JSON.stringify(fullRoot)),
        id: `${fullRoot.id}-batch-${i}`,
        children: part,
      },
    }));
  }

  return [
    {
      key: `${fullRoot.id}-single`,
      heading: `${domainLabel} (${children.length} branch${children.length !== 1 ? 'es' : ''})`,
      tree: fullRoot,
    },
  ];
}

const AttackSurface: React.FC = () => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [attackTreeRoot, setAttackTreeRoot] = useState<AttackTreeNode | null>(null);
  const [loading, setLoading] = useState(true);

  const normalizeTreeSubtitle = useCallback((t: AttackTreeNode): AttackTreeNode => {
    if (t.type === 'domain' && (!t.subtitle || t.subtitle === 'ROOT' || t.subtitle === 'Root node')) {
      return { ...t, subtitle: 'Domain' };
    }
    return t;
  }, []);

  const fetchGraph = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('accessToken');
      const workspaceId = localStorage.getItem('workspaceId');
      if (!token || !workspaceId) return;
      const res = await fetch(`${BACKEND_URL}/api/workspaces/${workspaceId}/attack-graph`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data: GraphData = await res.json();
      setGraphData(data);
      let tree =
        data.attackTree ??
        fallbackAttackTree({
          nodes: data.nodes || [],
          edges: data.edges || [],
          stats: data.stats || ({} as GraphStats),
          rootDomain: data.rootDomain,
        });
      tree = dedupeAttackTreeVulnerabilities(normalizeTreeSubtitle(tree));
      setAttackTreeRoot(tree);
    } catch (err) {
      console.error('Failed to fetch attack graph', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraph();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const stats = graphData?.stats;

  const treeSegments = attackTreeRoot ? splitTreesForAssets(attackTreeRoot) : [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-gradient-to-br from-brand/15 to-red-900/20 rounded-xl border border-brand/20">
            <Globe className="text-brand" size={22} />
          </div>
          <div>
            <h1 className="text-2xl font-black text-white tracking-tight">Attack tree</h1>
            <p className="text-sm text-[#6b7280] mt-0.5">
              Structured attack paths sourced from Assets domain and modeled findings — each vulnerability includes mitigation guidance.
            </p>
          </div>
        </div>
        <button
          onClick={fetchGraph}
          className="flex items-center gap-2 px-4 py-2 bg-[#1e262e] hover:bg-[#334155] text-[#9ca3af] hover:text-white rounded-lg text-sm font-medium transition-all border border-[#334155]"
        >
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 size={28} className="text-brand animate-spin" />
          <span className="ml-3 text-[#6b7280]">Building attack tree…</span>
        </div>
      ) : !attackTreeRoot ? (
        <div className="bg-[#0f1418]/60 border border-[#1e262e] rounded-xl p-12 text-center">
          <Crosshair size={40} className="text-[#334155] mx-auto mb-3" />
          <h3 className="text-lg font-bold text-[#9ca3af] mb-2">Unable to load attack tree</h3>
        </div>
      ) : (
        <>
          {stats ? (
            <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
              {[
                { label: 'Critical', value: stats.severityBreakdown.critical, color: 'text-red-400', icon: AlertTriangle },
                { label: 'High', value: stats.severityBreakdown.high, color: 'text-red-400', icon: Shield },
                { label: 'Medium', value: stats.severityBreakdown.medium, color: 'text-amber-400', icon: Target },
                { label: 'Low', value: stats.severityBreakdown.low, color: 'text-blue-400', icon: Lock },
                { label: 'Impact areas', value: stats.impactAreas, color: 'text-red-400', icon: TrendingUp },
              ].map((st) => (
                <div
                  key={st.label}
                  className="bg-[#0f1418]/80 backdrop-blur-xl border border-[#1e262e] rounded-xl p-4 text-center hover:border-[#64748b] transition-all"
                >
                  <st.icon size={16} className={`${st.color} mx-auto mb-2`} />
                  <p className={`text-2xl font-black ${st.color}`}>{st.value || 0}</p>
                  <p className="text-[10px] text-[#6b7280] uppercase font-bold tracking-wider mt-1">{st.label}</p>
                </div>
              ))}
            </div>
          ) : null}

          <div className="bg-[#0f1418]/80 backdrop-blur-xl border border-[#1e262e] rounded-2xl p-6">
            <h3 className="text-sm font-bold text-white mb-2 flex items-center gap-2">
              <GitBranch size={17} className="text-brand" />
              Threat tree visualization
              <span className="text-[10px] text-[#6b7280] font-normal lowercase tracking-normal">
                root = domain stored in Assets
              </span>
            </h3>
            <p className="text-xs text-[#6b7280] mb-4">
              Each <strong className="text-[#94a3b8] font-semibold">asset</strong> from your workspace renders as its own tree (scroll horizontally or vertically inside the panel). Finding counts are chunked into batches when a single asset has very many vulnerabilities so labels stay readable.
            </p>
            <div className="flex flex-col gap-8">
              {treeSegments.map((seg) => (
                <AttackTreeDiagram key={seg.key} root={seg.tree} heading={seg.heading} />
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default AttackSurface;
