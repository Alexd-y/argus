import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { LabExecutionRecord } from "@/lib/lab/types";

import { CaptureFullArtifactViewer } from "./CaptureFullArtifactViewer";

function execution(over: Partial<LabExecutionRecord> = {}): LabExecutionRecord {
  return {
    execution_id: "exec-1",
    lease_id: "lease-1",
    status: "completed",
    return_code: 0,
    stdout: "nuclei hit",
    stderr: "",
    runner: "lab-runner",
    argv: ["nuclei", "-u", "https://lab.argus"],
    error_code: null,
    requires_approval: false,
    capture_full: true,
    ...over,
  };
}

describe("CaptureFullArtifactViewer", () => {
  it("redacts stdout when capture_full is false", () => {
    render(
      <CaptureFullArtifactViewer
        executionId="exec-1"
        execution={execution({ capture_full: false })}
      />,
    );
    expect(screen.getByTestId("artifact-viewer-redacted")).toBeInTheDocument();
    expect(screen.queryByText("nuclei hit")).not.toBeInTheDocument();
  });

  it("shows stdout when capture_full is true", () => {
    render(
      <CaptureFullArtifactViewer
        executionId="exec-1"
        execution={execution({ capture_full: true, stdout: "nuclei hit" })}
      />,
    );
    expect(screen.getByTestId("artifact-viewer")).toHaveTextContent("nuclei hit");
    expect(screen.getByTestId("artifact-viewer-download")).toBeInTheDocument();
  });
});
