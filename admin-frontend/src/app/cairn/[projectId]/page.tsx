"use client";

import { use, useCallback, useEffect, useMemo, useState } from "react";
import {
  cairnApi,
  type CairnFact,
  type CairnIntent,
  type CairnProjectDetail,
} from "@/lib/cairnApi";

type LayoutNode = { ref: string; x: number; y: number; fact: CairnFact };

const COL_W = 220;
const ROW_H = 90;

function computeLayout(detail: CairnProjectDetail): {
  nodes: Map<string, LayoutNode>;
  width: number;
  height: number;
} {
  // Depth of each fact = shortest edge distance from origin along concluded intents.
  const depth = new Map<string, number>();
  depth.set("origin", 0);
  const edges: Array<[string, string]> = [];
  for (const intent of detail.intents) {
    const to = intent.to;
    if (!to) continue;
    for (const from of intent.from) edges.push([from, to]);
  }
  // Relax depths a few passes (graph is small).
  for (let pass = 0; pass < detail.facts.length + 1; pass++) {
    for (const [from, to] of edges) {
      const d = depth.get(from);
      if (d === undefined) continue;
      const cur = depth.get(to);
      if (cur === undefined || cur < d + 1) depth.set(to, d + 1);
    }
  }
  const maxDepth = Math.max(0, ...Array.from(depth.values()));
  // goal always sits in the last column.
  depth.set("goal", maxDepth + 1);

  const byCol = new Map<number, CairnFact[]>();
  for (const fact of detail.facts) {
    const col = depth.get(fact.id) ?? 1;
    const list = byCol.get(col) ?? [];
    list.push(fact);
    byCol.set(col, list);
  }
  const nodes = new Map<string, LayoutNode>();
  let maxRows = 1;
  for (const [col, facts] of byCol) {
    maxRows = Math.max(maxRows, facts.length);
    facts.forEach((fact, i) => {
      nodes.set(fact.id, { ref: fact.id, x: col * COL_W + 40, y: i * ROW_H + 40, fact });
    });
  }
  const width = (Math.max(0, ...Array.from(byCol.keys())) + 1) * COL_W + 80;
  const height = maxRows * ROW_H + 80;
  return { nodes, width, height };
}

function nodeColor(fact: CairnFact): string {
  if (fact.id === "origin") return "#6366f1";
  if (fact.id === "goal") return "#a855f7";
  if (fact.finding_id) return "#10b981";
  return "#334155";
}

function FactIntentGraph({ detail }: { detail: CairnProjectDetail }) {
  const { nodes, width, height } = useMemo(() => computeLayout(detail), [detail]);
  return (
    <div className="overflow-auto rounded border border-neutral-800 bg-neutral-950/40">
      <svg width={Math.max(width, 320)} height={Math.max(height, 160)} role="img" aria-label="Fact-Intent graph">
        {detail.intents.map((intent) => {
          const target = intent.to ? nodes.get(detail.facts.find((f) => f.id === intent.to)?.id ?? "") : null;
          const stroke = intent.concluded_at
            ? intent.to === "goal"
              ? "#a855f7"
              : "#10b981"
            : "#f59e0b";
          return intent.from.map((fromRef) => {
            const src = nodes.get(detail.facts.find((f) => f.id === fromRef)?.id ?? "");
            if (!src) return null;
            const tx = target ? target.x : src.x + COL_W - 40;
            const ty = target ? target.y : src.y;
            return (
              <line
                key={`${intent.id}-${fromRef}`}
                x1={src.x + 70}
                y1={src.y + 20}
                x2={tx}
                y2={ty + 20}
                stroke={stroke}
                strokeWidth={1.5}
                strokeDasharray={intent.concluded_at ? undefined : "4 3"}
              />
            );
          });
        })}
        {Array.from(nodes.values()).map((n) => (
          <g key={n.ref}>
            <rect x={n.x} y={n.y} width={150} height={40} rx={6} fill={nodeColor(n.fact)} opacity={0.85} />
            <text x={n.x + 8} y={n.y + 16} fill="#fff" fontSize={11} fontFamily="monospace">
              {n.ref}
            </text>
            <text x={n.x + 8} y={n.y + 31} fill="#e5e7eb" fontSize={9}>
              {n.fact.description.slice(0, 24)}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}

type TimelineEvent = { ts: string; text: string };

function buildTimeline(detail: CairnProjectDetail): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  events.push({ ts: detail.project.created_at, text: `PROJECT CREATED — ${detail.project.title}` });
  for (const h of detail.hints) events.push({ ts: h.created_at, text: `HINT by ${h.creator}: ${h.content}` });
  for (const i of detail.intents) {
    events.push({ ts: i.created_at, text: `INTENT ${i.id} declared by ${i.creator}` });
    if (i.concluded_at) {
      events.push({
        ts: i.concluded_at,
        text: i.to === "goal" ? `PROJECT COMPLETED via ${i.id}` : `INTENT ${i.id} concluded → ${i.to}`,
      });
    }
  }
  return events.sort((a, b) => (a.ts < b.ts ? -1 : 1));
}

export default function CairnProjectPage({ params }: { params: Promise<{ projectId: string }> }) {
  const { projectId } = use(params);
  const [detail, setDetail] = useState<CairnProjectDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [hint, setHint] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    cairnApi
      .getProject(projectId)
      .then(setDetail)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"))
      .finally(() => setLoading(false));
  }, [projectId]);

  useEffect(() => load(), [load]);

  const addHint = (e: React.FormEvent) => {
    e.preventDefault();
    if (!hint.trim()) return;
    cairnApi
      .addHint(projectId, hint.trim(), "admin")
      .then(() => {
        setHint("");
        load();
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"));
  };

  const setStatus = (status: "active" | "stopped") => {
    cairnApi.updateStatus(projectId, status).then(load).catch((e) => setError(e instanceof Error ? e.message : "Failed"));
  };

  if (loading) return <p className="text-neutral-500">Loading...</p>;
  if (error) return <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">{error}</div>;
  if (!detail) return null;

  const timeline = buildTimeline(detail);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">
            {detail.project.title} <span className="font-mono text-sm text-neutral-500">({detail.project.ref})</span>
          </h1>
          <p className="text-sm text-neutral-400">
            Status: <span className="font-medium">{detail.project.status}</span>
            {detail.project.reason?.worker && ` · reason worker: ${detail.project.reason.worker}`}
          </p>
        </div>
        <div className="flex gap-2">
          {detail.project.status === "active" && (
            <button onClick={() => setStatus("stopped")} className="rounded bg-amber-700 px-3 py-1.5 text-sm text-white hover:bg-amber-600">
              Stop
            </button>
          )}
          {detail.project.status === "stopped" && (
            <button onClick={() => setStatus("active")} className="rounded bg-emerald-700 px-3 py-1.5 text-sm text-white hover:bg-emerald-600">
              Resume
            </button>
          )}
        </div>
      </div>

      <section>
        <h2 className="mb-2 text-sm font-semibold text-neutral-300">Fact–Intent graph</h2>
        <FactIntentGraph detail={detail} />
        <p className="mt-1 text-xs text-neutral-500">
          Solid = concluded intent · dashed amber = open intent · purple = completion · green node = promoted to finding.
        </p>
      </section>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <section>
          <h2 className="mb-2 text-sm font-semibold text-neutral-300">Facts ({detail.facts.length})</h2>
          <ul className="space-y-1 text-sm">
            {detail.facts.map((f: CairnFact) => (
              <li key={f.id} className="rounded border border-neutral-800 p-2">
                <span className="font-mono text-xs text-indigo-400">{f.id}</span> — {f.description}
              </li>
            ))}
          </ul>
        </section>
        <section>
          <h2 className="mb-2 text-sm font-semibold text-neutral-300">Intents ({detail.intents.length})</h2>
          <ul className="space-y-1 text-sm">
            {detail.intents.map((i: CairnIntent) => (
              <li key={i.id} className="rounded border border-neutral-800 p-2">
                <span className="font-mono text-xs text-amber-400">{i.id}</span>{" "}
                <span className="text-neutral-500">[{i.from.join(", ")} → {i.to ?? "…"}]</span> {i.description}
                {i.worker && <span className="text-neutral-500"> · {i.worker}</span>}
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section>
        <h2 className="mb-2 text-sm font-semibold text-neutral-300">Hints — human in the loop</h2>
        <form onSubmit={addHint} className="mb-2 flex gap-2">
          <input
            value={hint}
            onChange={(e) => setHint(e.target.value)}
            placeholder="Add a hint (works in any status)"
            className="flex-1 rounded border border-neutral-600 bg-neutral-900 px-3 py-2 text-sm text-white placeholder:text-neutral-500"
          />
          <button type="submit" className="rounded bg-indigo-600 px-4 py-2 text-sm text-white hover:bg-indigo-500">
            Add hint
          </button>
        </form>
        <ul className="space-y-1 text-sm text-neutral-300">
          {detail.hints.map((h) => (
            <li key={h.id}>
              <span className="font-mono text-xs text-neutral-500">{h.id}</span> ({h.creator}) {h.content}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2 className="mb-2 text-sm font-semibold text-neutral-300">Timeline</h2>
        <ol className="space-y-1 text-xs text-neutral-400">
          {timeline.map((e, idx) => (
            <li key={idx}>
              <span className="text-neutral-600">{new Date(e.ts).toLocaleString()}</span> — {e.text}
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
