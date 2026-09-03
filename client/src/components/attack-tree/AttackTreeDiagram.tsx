import React, { useMemo, useState, useCallback, useId } from 'react';

export interface AttackTreeNode {
  id: string;
  type: 'domain' | 'surface' | 'vulnerability' | 'impact' | 'mitigation';
  label: string;
  fullLabel?: string;
  subtitle?: string;
  severity?: string;
  endpoint?: string;
  children?: AttackTreeNode[];
}

const BRAND = '#EE4344';

const BRANCH_PALETTE = ['#EE4344', '#F97316', '#64748B', '#CA8A04', '#0EA5E9'];

const SHADOW_OFFSET = { x: 5, y: 6 };

type WithLayout = AttackTreeNode & {
  _lx?: number;
  _absX?: number;
  _absY?: number;
  _bw?: number;
  _bh?: number;
  _shade?: string;
};

function severityShade(sev?: string): string {
  switch ((sev || '').toLowerCase()) {
    case 'critical':
      return '#991B1B';
    case 'high':
      return '#B91C1C';
    case 'medium':
      return '#CA8A04';
    case 'low':
      return '#2563EB';
    default:
      return '#64748b';
  }
}

function backingForType(t: AttackTreeNode['type'], branchIndex: number, sev?: string): string {
  if (t === 'domain') return BRAND;
  if (t === 'mitigation') return '#15803D';
  if (t === 'vulnerability') return severityShade(sev);
  if (t === 'impact') return '#92400e';
  return BRANCH_PALETTE[(branchIndex + 1) % BRANCH_PALETTE.length];
}

function treeVulnCanonicalKey(n: AttackTreeNode): string {
  const b = `${n.label} ${n.fullLabel || ''}`.toLowerCase();
  if (/default\s*password|weak\s*credential|broken\s*authentication|credential|auth\s*bypass|bypass\s*auth|password\s*issue/i.test(b))
    return 'cls:auth-weakness';
  if (/(^|\b)sqli\b|sql\s*inj|sql\s*injection/i.test(b)) return 'cls:sqli';
  if (/cross[-\s]?site|\bxss\b/i.test(b)) return 'cls:xss';
  if (/\bidor\b|insecure\s*direct/i.test(b)) return 'cls:idor';
  if (/\bssrf\b/i.test(b)) return 'cls:ssrf';
  if (/\bcsrf\b/i.test(b)) return 'cls:csrf';
  if (/\blfi\b|path\s*traversal|\btraversal\b|directory\s*listing/i.test(b)) return 'cls:lfi';
  if (/\bssti\b|template\s*inj/i.test(b)) return 'cls:ssti';
  if (/\brce\b|command\s*inj/i.test(b)) return 'cls:rce';
  if (/jwt\b/i.test(b)) return 'cls:jwt';
  if (/open\s*redirect/i.test(b)) return 'cls:open-redirect';
  return `raw:${b.replace(/\s+/g, ' ').trim().slice(0, 100)}`;
}

const CANON_LABELS: Record<string, string> = {
  'cls:auth-weakness': 'Broken / weak authentication',
  'cls:sqli': 'SQL Injection',
  'cls:xss': 'XSS',
  'cls:idor': 'IDOR',
  'cls:ssrf': 'SSRF',
  'cls:csrf': 'CSRF',
  'cls:lfi': 'Path / LFI',
  'cls:ssti': 'SSTI',
  'cls:rce': 'RCE / Command injection',
  'cls:jwt': 'JWT weakness',
  'cls:open-redirect': 'Open redirect',
};

function severityRank(s?: string): number {
  const m: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0, informational: 0 };
  return m[(s || '').toLowerCase()] ?? 1;
}

/**
 * Merge duplicate vulnerability siblings (same class) under each parent — keeps one node per issue class.
 */
export function dedupeAttackTreeVulnerabilities(root: AttackTreeNode): AttackTreeNode {
  const r = JSON.parse(JSON.stringify(root)) as AttackTreeNode;

  function process(node: AttackTreeNode) {
    if (!node.children?.length) return;
    for (const ch of node.children) process(ch);

    const nonV: AttackTreeNode[] = [];
    const vulns: AttackTreeNode[] = [];
    for (const c of node.children) {
      if (c.type === 'vulnerability') vulns.push(c);
      else nonV.push(c);
    }
    if (vulns.length <= 1) return;

    const buckets = new Map<string, AttackTreeNode[]>();
    for (const v of vulns) {
      const k = treeVulnCanonicalKey(v);
      if (!buckets.has(k)) buckets.set(k, []);
      buckets.get(k)!.push(v);
    }

    const mergedList: AttackTreeNode[] = [];
    for (const [, group] of buckets) {
      if (group.length === 1) {
        mergedList.push(group[0]);
        continue;
      }
      group.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
      const primary = { ...group[0] };
      const key = treeVulnCanonicalKey(primary);
      const pretty = CANON_LABELS[key] || primary.fullLabel || primary.label;
      primary.label = pretty.length > 48 ? `${pretty.slice(0, 46)}…` : pretty;
      primary.fullLabel = pretty;
      primary.severity = group[0].severity;
      primary.subtitle = `${group.length}× in scope`;
      const eps = [...new Set(group.map((g) => g.endpoint).filter(Boolean))] as string[];
      if (eps.length) primary.endpoint = eps.join(' · ').slice(0, 900);
      primary.id = `dedupe-${key.replace(/[^a-z0-9]+/gi, '-')}`;
      mergedList.push(primary);
    }

    node.children = [...nonV, ...mergedList];
  }

  process(r);
  return r;
}

let leafIx = 0;

function assignLeafX(n: AttackTreeNode): void {
  if (!n.children?.length) {
    (n as WithLayout)._lx = leafIx++;
    return;
  }
  n.children.forEach(assignLeafX);
  const xs = n.children.map((c) => (c as WithLayout)._lx!).sort((a, b) => a - b);
  (n as WithLayout)._lx = (xs[0] + xs[xs.length - 1]) / 2;
}

function countLeafNodes(n: AttackTreeNode): number {
  if (!n.children?.length) return 1;
  return n.children.reduce((s, ch) => s + countLeafNodes(ch), 0);
}

function layoutParameters(root: AttackTreeNode): { vert: number; xSpace: number } {
  const leaves = Math.max(1, countLeafNodes(root));
  const xSpace = Math.max(148, Math.min(320, Math.floor(4200 / Math.sqrt(leaves + 10))));
  const vert = leaves > 40 ? 185 : leaves > 25 ? 210 : leaves > 15 ? 230 : 255;
  return { vert, xSpace };
}

function collectNodes(rawRoot: AttackTreeNode): WithLayout[] {
  leafIx = 0;
  assignLeafX(rawRoot);

  const { vert: VERT, xSpace: X_SPACE } = layoutParameters(rawRoot);
  const Y0 = 40;
  const MARGIN_L = 72;

  const list: WithLayout[] = [];

  function measureBox(node: AttackTreeNode): { w: number; h: number } {
    const lw =
      node.type === 'mitigation'
        ? Math.max(node.label?.length ?? 12, 24)
        : Math.max(node.label?.length ?? 8, Math.min(node.fullLabel?.length ?? 0, 90));
    const baseW = Math.min(342, Math.max(132, lw * (node.type === 'mitigation' ? 6.9 : 7.6) + 44));
    const h =
      node.type === 'domain' ? 72 : node.type === 'surface' ? 64 : node.type === 'mitigation' ? 66 : 62;
    return { w: baseW, h };
  }

  function walk(n: AttackTreeNode, depth: number, branchIndex: number) {
    const { w: bw, h: bh } = measureBox(n);
    const lx = (n as WithLayout)._lx ?? 0;
    const wl: WithLayout = {
      ...n,
      _absX: MARGIN_L + lx * X_SPACE,
      _absY: Y0 + depth * VERT,
      _bw: bw,
      _bh: bh,
      _shade: backingForType(n.type, branchIndex, n.severity),
    };
    list.push(wl);
    n.children?.forEach((ch, i) => walk(ch, depth + 1, i));
  }

  walk(rawRoot, 0, 0);

  const centers = list.map((p) => p._absX!);
  const mids = [(Math.min(...centers) + Math.max(...centers)) / 2, vbCenterTarget(list)];
  const shift = mids[1] - mids[0];
  list.forEach((p) => {
    p._absX! += shift;
  });

  return list;
}

function vbCenterTarget(nodes: WithLayout[]): number {
  if (!nodes.length) return 620;
  const mw = nodes.reduce((mx, n) => Math.max(mx, n._bw!), 140);
  return Math.max(...nodes.map((n) => n._absX!)) / 2 + mw / 4;
}

function edgesFromRoot(root: AttackTreeNode, nodes: WithLayout[]): { from: WithLayout; to: WithLayout; curved: boolean; color: string }[] {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const edges: { from: WithLayout; to: WithLayout; curved: boolean; color: string }[] = [];

  function walk(parent: AttackTreeNode) {
    const p = byId.get(parent.id);
    parent.children?.forEach((ch) => {
      const c = byId.get(ch.id);
      if (!p || !c) return;
      const curved = p.type === 'domain' || p.type === 'surface';
      edges.push({ from: p, to: c, curved, color: c._shade || BRAND });
      walk(ch);
    });
  }

  walk(root);
  return edges;
}

export const AttackTreeDiagram: React.FC<{
  root: AttackTreeNode;
  /** Shown above the diagram (e.g. asset URL) */
  heading?: string;
}> = ({ root, heading }) => {
  const [sel, setSel] = useState<WithLayout | null>(null);
  const rid = useId().replace(/:/g, '');

  const cloned = useMemo(
    () => dedupeAttackTreeVulnerabilities(JSON.parse(JSON.stringify(root)) as AttackTreeNode),
    [root]
  );

  const laid = useMemo(() => collectNodes(cloned), [cloned]);
  const edges = useMemo(() => edgesFromRoot(cloned, laid), [cloned, laid]);

  const pad = { t: 36, r: 72, b: 72, l: 72 };

  const maxXExt = laid.length ? Math.max(...laid.map((p) => p._absX! + p._bw! / 2)) : 800;
  const minXExt = laid.length ? Math.min(...laid.map((p) => p._absX! - p._bw! / 2)) : 0;
  const maxYExt = laid.length ? Math.max(...laid.map((p) => p._absY! + p._bh!)) : 460;

  const vbW = maxXExt + pad.r - (minXExt - pad.l);
  const vbH = maxYExt + pad.t + pad.b;

  const svgMinX = minXExt - pad.l;

  const svgToLocal = useCallback(
    (n: WithLayout) => ({
      px: n._absX!,
      py: n._absY! + pad.t,
    }),
    [pad.t]
  );

  const markerParent = `${rid}-at-arrow-parent`;
  const markerSeq = `${rid}-at-arrow-seq`;

  /** Use 1:1 pixel size for viewBox so the tree does not shrink into an unreadable strip */
  const pixelW = Math.ceil(Math.max(vbW, 640));
  const pixelH = Math.ceil(Math.max(vbH, 420));

  return (
    <div className="relative w-full rounded-xl border border-zinc-700/90 shadow-inner shadow-black/15 bg-[#0f0f17] overflow-hidden">
      {heading ? (
        <div className="px-5 py-3 border-b border-[#1e262e] bg-[#0a0d12] flex items-center justify-between gap-3">
          <p className="text-sm font-bold text-white truncate" title={heading}>
            {heading}
          </p>
          <span className="text-[10px] text-[#6b7280] shrink-0 font-semibold uppercase tracking-wider hidden sm:inline">
            Scroll sideways if wide
          </span>
        </div>
      ) : null}
      <div className="relative w-full overflow-x-auto overflow-y-auto max-h-[min(85vh,1100px)] bg-[#f4f2ee]" style={{ minWidth: pixelW }}>
        <svg
          width={pixelW}
          height={pixelH}
          viewBox={`${svgMinX} 0 ${vbW} ${vbH}`}
          className="block mx-auto"
          preserveAspectRatio="xMinYMin meet"
          role="img"
          aria-label={heading ? `Attack tree: ${heading}` : 'Attack tree diagram'}
        >
          <defs>
            <marker id={markerParent} markerWidth="10" markerHeight="8" refX="9" refY="4" orient="auto">
              <polygon points="0 0, 10 4, 0 8" fill={BRAND} opacity="0.88" />
            </marker>
            <marker id={markerSeq} markerWidth="10" markerHeight="8" refX="9" refY="4" orient="auto">
              <polygon points="0 0, 10 4, 0 8" fill="#f87171" opacity="0.95" />
            </marker>
          </defs>

          <rect x={svgMinX - 600} y={-200} width={vbW + 1200} height={vbH + 400} fill="#faf8f5" />

          <g opacity={0.93}>
            {edges.map((e, i) => {
              const a = svgToLocal(e.from);
              const b = svgToLocal(e.to);
              const x1 = a.px,
                y1 = a.py + e.from._bh!;
              const x2 = b.px,
                y2 = b.py;

              let d: string;
              if (e.curved) {
                const my = y1 + (y2 - y1) * 0.42;
                d = `M ${x1} ${y1} C ${x1} ${my}, ${x2} ${my}, ${x2} ${y2}`;
              } else {
                d = `M ${x1} ${y1} L ${x2} ${y2 - 4}`;
              }

              const mark = e.curved ? markerParent : markerSeq;

              return (
                <path
                  key={`e-${i}-${e.from.id}-${e.to.id}`}
                  d={d}
                  fill="none"
                  stroke={e.curved ? e.color : BRAND}
                  strokeWidth={e.curved ? 2.05 : 2.15}
                  strokeOpacity={curvedOpacity(e.curved)}
                  markerEnd={`url(#${mark})`}
                />
              );
            })}
          </g>

          <g>
            {laid.map((n, i) => {
              const { px, py } = svgToLocal(n);
              const w = n._bw!;
              const h = n._bh!;
              const sx = px - w / 2;
              const sy = py;
              const isSel = sel?.id === n.id;
              const shadowClr = n._shade || BRAND;
              const isMit = n.type === 'mitigation';
              const subY = Boolean(n.subtitle && n.subtitle.trim());

              return (
                <g
                  key={`${n.id}-${i}`}
                  style={{ cursor: 'pointer' }}
                  onClick={() =>
                    setSel((s) => (s?.id === n.id ? null : n))
                  }
                >
                  <title>{n.fullLabel || n.label}</title>
                  <rect
                    x={sx + SHADOW_OFFSET.x}
                    y={sy + SHADOW_OFFSET.y}
                    width={w}
                    height={h}
                    rx={14}
                    fill={shadowClr}
                    opacity={0.9}
                  />
                  <rect
                    x={sx}
                    y={sy}
                    width={w}
                    height={h}
                    rx={14}
                    fill={isMit ? '#f0fdf4' : '#ffffff'}
                    stroke={isSel ? BRAND : isMit ? '#bbf7d0' : '#e2e8f0'}
                    strokeWidth={isSel ? 2.2 : 1.15}
                  />
                  {subY && (
                    <text
                      x={px}
                      y={sy + 21}
                      textAnchor="middle"
                      fill={isMit ? '#166534' : '#64748b'}
                      fontSize="11"
                      fontWeight="700"
                      fontFamily="system-ui, sans-serif"
                      letterSpacing="0.06em"
                    >
                      {(n.subtitle ?? '').toUpperCase()}
                    </text>
                  )}
                  <foreignObject
                    x={sx + 10}
                    y={sy + (subY ? 28 : 14)}
                    width={w - 20}
                    height={h - (subY ? 38 : 26)}
                  >
                    <div
                      xmlns="http://www.w3.org/1999/xhtml"
                      className="flex flex-col justify-center items-center text-center px-2 h-full"
                      style={{ fontFamily: "'Inter', system-ui, sans-serif" }}
                    >
                      <span
                        className={
                          n.type === 'domain'
                            ? 'text-[18px] font-extrabold text-slate-900 leading-snug tracking-tight'
                            : n.type === 'mitigation'
                              ? 'text-[13px] font-semibold text-green-950 leading-snug'
                              : 'text-[15px] font-bold text-slate-900 leading-snug'
                        }
                      >
                        {n.label}
                      </span>
                    </div>
                  </foreignObject>

                  {n.type === 'vulnerability' && n.severity && (
                    <text
                      x={px}
                      y={sy + h - 7}
                      textAnchor="middle"
                      fill={severityShade(n.severity)}
                      fontSize="10.5"
                      fontWeight="900"
                      fontFamily="system-ui"
                      letterSpacing="0.1em"
                    >
                      {(n.severity ?? '').toUpperCase()}
                    </text>
                  )}
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {sel && (
        <div className="border-t border-[#1e262e] bg-[#0a0d12] p-5 text-sm">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="text-[10px] uppercase font-black tracking-widest text-brand mb-1">
                {sel.type.replace('-', ' ')}
              </p>
              <h4 className="text-white font-bold text-lg leading-snug">{sel.fullLabel ?? sel.label}</h4>
              {sel.endpoint ? (
                <code className="mt-2 inline-block max-w-full text-xs bg-black/40 border border-[#1e262e] rounded px-2 py-1 text-red-400 break-all">
                  {sel.endpoint}
                </code>
              ) : null}
              {sel.type === 'mitigation' ||
              sel.type === 'impact' ||
              ((sel.fullLabel ?? sel.label) && (sel.fullLabel ?? sel.label) !== sel.label) ? (
                <p className="mt-3 text-[#94a3b8] whitespace-pre-wrap leading-relaxed text-[13px]">
                  {sel.type === 'mitigation' || sel.type === 'impact' ? sel.fullLabel ?? sel.label : sel.fullLabel}
                </p>
              ) : null}
            </div>
            <button type="button" onClick={() => setSel(null)} className="shrink-0 text-[11px] text-[#6b7280] hover:text-white font-bold uppercase tracking-wider">
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

function curvedOpacity(curved: boolean) {
  return curved ? 0.58 : 0.62;
}

export default AttackTreeDiagram;
