"use client";

import { useCallback, useEffect, useState } from "react";

import { LabKillSwitchControl } from "@/components/LabKillSwitchControl";
import { LabUnrestrictedBadge } from "@/components/LabUnrestrictedBadge";
import { scanApi } from "@/lib/scanApi";

interface LabWorkspaceProps {
  title: string;
}

export function LabWorkspace({ title }: LabWorkspaceProps) {
  const [scanId, setScanId] = useState("scan-1");
  const [profiles, setProfiles] = useState<Array<Record<string, unknown>>>([]);
  const [templates, setTemplates] = useState<Array<Record<string, unknown>>>([]);
  const [citations, setCitations] = useState<Array<Record<string, unknown>>>([]);
  const [oast, setOast] = useState<Array<Record<string, unknown>>>([]);
  const [plan, setPlan] = useState(
    JSON.stringify(
      {
        mode: "lab_unrestricted",
        tools: ["nuclei", "sqlmap", "custom_script"],
        templates: ["unsigned", "code", "headless"],
        requires_approval: false,
      },
      null,
      2
    )
  );
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    Promise.all([
      scanApi.listNucleiProfiles(),
      scanApi.listNucleiTemplates(),
      scanApi.getRagTrace(scanId),
      scanApi.getOastTrace(scanId),
    ])
      .then(([p, t, rag, oastTrace]) => {
        setProfiles(p.profiles);
        setTemplates(t.templates);
        setCitations(rag.citations);
        setOast(oastTrace.interactions);
        setError(null);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"));
  }, [scanId]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">{title}</h1>
        <LabUnrestrictedBadge />
      </div>
      <p className="text-sm text-neutral-400">
        LAB capabilities are not filtered by production risk labels. Approval
        dialogs are skipped when a usable lease is active.
      </p>
      <LabKillSwitchControl enabled />

      <label className="block text-sm text-neutral-300">
        Scan ID
        <input
          className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-2"
          value={scanId}
          onChange={(e) => setScanId(e.target.value)}
        />
      </label>

      {error ? (
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
          {error}
        </div>
      ) : null}

      <section className="rounded border border-neutral-800 p-4">
        <h2 className="mb-2 font-medium">Tool / template / script plan</h2>
        <textarea
          className="h-40 w-full rounded border border-neutral-700 bg-neutral-950 p-3 font-mono text-sm"
          value={plan}
          onChange={(e) => setPlan(e.target.value)}
        />
      </section>

      <section className="rounded border border-neutral-800 p-4">
        <h2 className="mb-2 font-medium">Nuclei profiles</h2>
        <pre className="overflow-auto text-xs text-neutral-300">
          {JSON.stringify(profiles, null, 2)}
        </pre>
      </section>

      <section className="rounded border border-neutral-800 p-4">
        <h2 className="mb-2 font-medium">Nuclei templates / releases</h2>
        <pre className="overflow-auto text-xs text-neutral-300">
          {JSON.stringify(templates, null, 2)}
        </pre>
      </section>

      <section className="rounded border border-neutral-800 p-4">
        <h2 className="mb-2 font-medium">RAG citation trace</h2>
        <pre className="overflow-auto text-xs text-neutral-300">
          {JSON.stringify(citations, null, 2)}
        </pre>
      </section>

      <section className="rounded border border-neutral-800 p-4">
        <h2 className="mb-2 font-medium">OAST interactions</h2>
        <pre className="overflow-auto text-xs text-neutral-300">
          {JSON.stringify(oast, null, 2)}
        </pre>
      </section>
    </div>
  );
}
