"use client";

import { useState } from "react";

import {
  LAB_DEFAULT_TEMPLATES,
  LAB_DEFAULT_TOOLS,
  addPlanStep,
  normalizeLabPlan,
  removePlanStep,
} from "@/lib/lab/labApproval";
import type { LabScanPlan, PlanStepKind } from "@/lib/lab/types";

interface PlanEditorProps {
  plan: LabScanPlan;
  onChange: (plan: LabScanPlan) => void;
}

function kindLabel(kind: PlanStepKind): string {
  switch (kind) {
    case "tool":
      return "Tool";
    case "template":
      return "Template";
    case "script":
      return "Script";
    default: {
      const _exhaustive: never = kind;
      return _exhaustive;
    }
  }
}

/** Structured tool/template/script plan. LAB never filters by production risk. */
export function PlanEditor({ plan, onChange }: PlanEditorProps) {
  const [kind, setKind] = useState<PlanStepKind>("tool");
  const [name, setName] = useState("");
  const normalized = normalizeLabPlan(plan);
  const suggestions = kind === "template" ? LAB_DEFAULT_TEMPLATES : LAB_DEFAULT_TOOLS;

  return (
    <section className="rounded border border-neutral-800 p-4" data-testid="lab-plan-editor">
      <h2 className="mb-2 font-medium text-white">Tool / template / script plan</h2>
      <p className="mb-3 text-xs text-neutral-500">
        LAB capabilities are not filtered by production risk labels.
        {normalized.mode === "lab_unrestricted"
          ? " requires_approval is locked false."
          : null}
      </p>
      <p className="mb-3 font-mono text-xs text-neutral-400" data-testid="lab-plan-approval">
        requires_approval={String(normalized.requires_approval)}
      </p>
      <div className="mb-3 flex flex-wrap gap-2">
        <select
          className="rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-sm text-white"
          value={kind}
          onChange={(event) => setKind(event.target.value as PlanStepKind)}
          data-testid="lab-plan-kind"
        >
          <option value="tool">tool</option>
          <option value="template">template</option>
          <option value="script">script</option>
        </select>
        <input
          className="min-w-[12rem] flex-1 rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-sm text-white"
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder={kind === "template" ? "unsigned / code / headless" : "nuclei / sqlmap"}
          data-testid="lab-plan-name"
        />
        <button
          type="button"
          className="rounded bg-indigo-700 px-3 py-1 text-sm text-white hover:bg-indigo-600"
          data-testid="lab-plan-add"
          onClick={() => {
            onChange(addPlanStep(normalized, kind, name));
            setName("");
          }}
        >
          Add
        </button>
      </div>
      <div className="mb-3 flex flex-wrap gap-1">
        {suggestions.map((item) => (
          <button
            key={item}
            type="button"
            className="rounded border border-neutral-700 px-2 py-0.5 text-xs text-neutral-300 hover:border-amber-500"
            onClick={() => onChange(addPlanStep(normalized, kind, item))}
          >
            {item}
          </button>
        ))}
      </div>
      <ul className="space-y-1" data-testid="lab-plan-steps">
        {normalized.steps.length === 0 ? (
          <li className="text-xs text-neutral-600">No steps yet</li>
        ) : (
          normalized.steps.map((step) => (
            <li
              key={step.id}
              className="flex items-center justify-between rounded border border-neutral-800 bg-neutral-950 px-2 py-1 text-sm"
            >
              <span className="font-mono text-neutral-200">
                {kindLabel(step.kind)} · {step.name}
              </span>
              <button
                type="button"
                className="text-xs text-red-300 hover:text-red-200"
                onClick={() => onChange(removePlanStep(normalized, step.id))}
              >
                Remove
              </button>
            </li>
          ))
        )}
      </ul>
    </section>
  );
}
