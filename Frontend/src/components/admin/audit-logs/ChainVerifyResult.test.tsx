import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ChainVerifyResult } from "./ChainVerifyResult";
import type { AuditChainVerifyResponse } from "@/lib/adminAuditLogs";

const SAMPLE_TS = "2026-04-21T08:00:00Z";

function okResult(over: Partial<AuditChainVerifyResponse> = {}): AuditChainVerifyResponse {
  return {
    ok: true,
    verified_count: 12,
    last_verified_index: 11,
    drift_event_id: null,
    drift_detected_at: null,
    effective_since: SAMPLE_TS,
    effective_until: SAMPLE_TS,
    ...over,
  };
}

function driftResult(over: Partial<AuditChainVerifyResponse> = {}): AuditChainVerifyResponse {
  return {
    ok: false,
    verified_count: 5,
    last_verified_index: 4,
    drift_event_id: "evt-drift",
    drift_detected_at: SAMPLE_TS,
    effective_since: SAMPLE_TS,
    effective_until: SAMPLE_TS,
    ...over,
  };
}

describe("ChainVerifyResult", () => {
  it("renders nothing when no result, no error and not verifying", () => {
    const { container } = render(
      <ChainVerifyResult result={null} verifying={false} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders a polite status banner with verified count and effective window for OK result", () => {
    render(<ChainVerifyResult result={okResult({ verified_count: 42 })} />);

    const banner = screen.getByTestId("audit-chain-ok");
    expect(banner).toHaveAttribute("role", "status");
    expect(banner).toHaveAttribute("aria-live", "polite");
    expect(banner.textContent ?? "").toMatch(/42/);
    expect(banner.textContent ?? "").toMatch(/Окно/);
  });

  it("renders an alert banner with drift attribution for DRIFT result", () => {
    render(<ChainVerifyResult result={driftResult()} />);

    const banner = screen.getByTestId("audit-chain-drift");
    expect(banner).toHaveAttribute("role", "alert");
    expect(banner.textContent ?? "").toMatch(/расхожд/);
    expect(banner.textContent ?? "").toContain("evt-drift");
  });

  it("renders a verifying status when the verification is in flight", () => {
    render(<ChainVerifyResult result={null} verifying />);
    const status = screen.getByTestId("audit-chain-verifying");
    expect(status).toHaveAttribute("role", "status");
    expect(status.textContent ?? "").toMatch(/Проверяем/);
  });

  it("renders the closed-taxonomy error banner when errorMessage is provided", () => {
    render(
      <ChainVerifyResult
        result={null}
        errorMessage="Недостаточно прав для просмотра audit log."
      />,
    );
    const err = screen.getByTestId("audit-chain-error");
    expect(err).toHaveAttribute("role", "alert");
    expect(err.textContent ?? "").not.toMatch(/stack|trace/i);
  });

  it("'Прокрутить к записи' button shows only when drift_event_id is loaded in the table", async () => {
    const user = userEvent.setup();
    const onJump = vi.fn();
    const { rerender } = render(
      <ChainVerifyResult
        result={driftResult()}
        onJumpToDrift={onJump}
        canJumpToDrift={false}
      />,
    );
    expect(screen.queryByTestId("audit-chain-jump")).not.toBeInTheDocument();

    rerender(
      <ChainVerifyResult
        result={driftResult()}
        onJumpToDrift={onJump}
        canJumpToDrift
      />,
    );
    const jump = screen.getByTestId("audit-chain-jump");
    await user.click(jump);
    expect(onJump).toHaveBeenCalledWith("evt-drift");
  });

  it("dismiss button fires onDismiss for both OK and DRIFT banners", async () => {
    const user = userEvent.setup();
    const onDismiss = vi.fn();
    const { rerender } = render(
      <ChainVerifyResult result={okResult()} onDismiss={onDismiss} />,
    );
    await user.click(screen.getByTestId("audit-chain-dismiss"));
    expect(onDismiss).toHaveBeenCalledTimes(1);

    rerender(
      <ChainVerifyResult result={driftResult()} onDismiss={onDismiss} />,
    );
    await user.click(screen.getByTestId("audit-chain-dismiss"));
    expect(onDismiss).toHaveBeenCalledTimes(2);
  });
});
