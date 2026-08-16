"use client";

import { useEffect, useState } from "react";

import { labApi } from "@/lib/lab/labApi";
import type { LlmRoutingHealth } from "@/lib/lab/types";

export function RoutingHealthView() {
  const [health, setHealth] = useState<LlmRoutingHealth | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void labApi
      .getLlmRoutingHealth()
      .then((payload) => {
        if (!cancelled) setHealth(payload);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "health_failed");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return (
      <p className="text-xs text-red-400" data-testid="routing-health-error">
        {error}
      </p>
    );
  }
  if (!health) {
    return <p className="text-xs text-neutral-500">Loading routing health…</p>;
  }

  return (
    <section className="rounded border border-neutral-800 p-4" data-testid="routing-health">
      <h2 className="mb-2 font-medium text-white">Model routing / provider health</h2>
      <dl className="grid gap-1 font-mono text-xs text-neutral-300 sm:grid-cols-2">
        <div>
          <dt className="inline text-neutral-500">routing_mode: </dt>
          <dd className="inline" data-testid="routing-mode">
            {health.routing_mode}
          </dd>
        </div>
        <div>
          <dt className="inline text-neutral-500">wrb: </dt>
          <dd className="inline">{health.whiteRabbitNeo.status}</dd>
        </div>
        <div>
          <dt className="inline text-neutral-500">cloud: </dt>
          <dd className="inline">{health.cloud.status}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="inline text-neutral-500">wrb_model: </dt>
          <dd className="inline">{health.whiteRabbitNeo.model ?? "—"}</dd>
        </div>
      </dl>
    </section>
  );
}
