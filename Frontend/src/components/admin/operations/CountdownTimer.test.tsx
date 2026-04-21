import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen } from "@testing-library/react";

import { CountdownTimer } from "./CountdownTimer";

const FIXED_NOW = Date.parse("2026-04-22T00:00:00.000Z");

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date(FIXED_NOW));
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function expiresAt(seconds: number): string {
  return new Date(FIXED_NOW + seconds * 1000).toISOString();
}

describe("CountdownTimer — rendering", () => {
  it("renders MM:SS for sub-hour durations", () => {
    render(<CountdownTimer expiresAt={expiresAt(75)} />);
    const node = screen.getByTestId("countdown-timer");
    expect(node.textContent).toBe("01:15");
    expect(node.getAttribute("data-format")).toBe("MM:SS");
  });

  it("renders HH:MM:SS for >=1h durations", () => {
    render(<CountdownTimer expiresAt={expiresAt(3 * 60 * 60 + 5 * 60 + 9)} />);
    const node = screen.getByTestId("countdown-timer");
    expect(node.textContent).toBe("03:05:09");
    expect(node.getAttribute("data-format")).toBe("HH:MM:SS");
  });

  it("clamps negative remaining (already-expired prop) to 00:00", () => {
    render(<CountdownTimer expiresAt={expiresAt(-30)} />);
    expect(screen.getByTestId("countdown-timer").textContent).toBe("00:00");
  });

  it("treats unparseable expiresAt as zero", () => {
    render(<CountdownTimer expiresAt="not-a-date" />);
    expect(screen.getByTestId("countdown-timer").textContent).toBe("00:00");
  });

  it("applies className + ariaLabel", () => {
    render(
      <CountdownTimer
        expiresAt={expiresAt(60)}
        className="text-amber-200"
        ariaLabel="Time remaining for tenant Acme throttle"
      />,
    );
    const node = screen.getByTestId("countdown-timer");
    expect(node).toHaveAttribute(
      "aria-label",
      "Time remaining for tenant Acme throttle",
    );
    expect(node).toHaveAttribute("aria-live", "polite");
    expect(node.className).toContain("text-amber-200");
  });
});

describe("CountdownTimer — ticking", () => {
  it("decrements once per second", () => {
    render(<CountdownTimer expiresAt={expiresAt(5)} />);
    const node = screen.getByTestId("countdown-timer");
    expect(node.textContent).toBe("00:05");

    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(node.textContent).toBe("00:04");

    act(() => {
      vi.advanceTimersByTime(2000);
    });
    expect(node.textContent).toBe("00:02");
  });

  it("recomputes from wall-clock so a long-paused interval lands on the right value", () => {
    render(<CountdownTimer expiresAt={expiresAt(120)} />);
    const node = screen.getByTestId("countdown-timer");
    expect(node.textContent).toBe("02:00");

    // Tab backgrounded — browser delays interval, but Date.now() advances.
    act(() => {
      vi.advanceTimersByTime(45_000);
    });
    expect(node.textContent).toBe("01:15");
  });

  it("calls onExpire exactly once when the timer reaches zero", () => {
    const onExpire = vi.fn();
    render(<CountdownTimer expiresAt={expiresAt(2)} onExpire={onExpire} />);
    expect(onExpire).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(2_000);
    });
    expect(onExpire).toHaveBeenCalledTimes(1);

    // Continue ticking — must NOT fire again for the same expiresAt instant.
    act(() => {
      vi.advanceTimersByTime(5_000);
    });
    expect(onExpire).toHaveBeenCalledTimes(1);
  });

  it("fires onExpire immediately when mounted with an already-expired prop", () => {
    const onExpire = vi.fn();
    render(<CountdownTimer expiresAt={expiresAt(-10)} onExpire={onExpire} />);
    expect(onExpire).toHaveBeenCalledTimes(1);
  });

  it("re-arms the onExpire guard when expiresAt prop changes", () => {
    const onExpire = vi.fn();
    const { rerender } = render(
      <CountdownTimer expiresAt={expiresAt(2)} onExpire={onExpire} />,
    );
    act(() => {
      vi.advanceTimersByTime(2_000);
    });
    expect(onExpire).toHaveBeenCalledTimes(1);

    // System time is now FIXED_NOW + 2s. New expiresAt is 6s past origin
    // (i.e. 4s into the future from "now").
    rerender(
      <CountdownTimer expiresAt={expiresAt(6)} onExpire={onExpire} />,
    );
    expect(onExpire).toHaveBeenCalledTimes(1);

    act(() => {
      vi.advanceTimersByTime(4_000);
    });
    expect(onExpire).toHaveBeenCalledTimes(2);
  });

  it("cleans up the interval on unmount", () => {
    const onExpire = vi.fn();
    const { unmount } = render(
      <CountdownTimer expiresAt={expiresAt(5)} onExpire={onExpire} />,
    );
    unmount();
    act(() => {
      vi.advanceTimersByTime(10_000);
    });
    expect(onExpire).not.toHaveBeenCalled();
  });
});

describe("CountdownTimer — accessibility", () => {
  it("uses polite aria-live so the AT does not interrupt every second", () => {
    render(<CountdownTimer expiresAt={expiresAt(60)} />);
    const node = screen.getByTestId("countdown-timer");
    expect(node).toHaveAttribute("aria-live", "polite");
    expect(node).toHaveAttribute("aria-atomic", "true");
  });

  it("does not set role=timer (intentional — see component docstring)", () => {
    render(<CountdownTimer expiresAt={expiresAt(60)} />);
    expect(screen.getByTestId("countdown-timer")).not.toHaveAttribute(
      "role",
      "timer",
    );
  });
});
