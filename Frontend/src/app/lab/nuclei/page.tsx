"use client";

import { LabWorkspace } from "@/components/lab/LabWorkspace";

export default function LabNucleiPage() {
  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100">
      <LabWorkspace title="Nuclei control plane" showNuclei />
    </div>
  );
}
