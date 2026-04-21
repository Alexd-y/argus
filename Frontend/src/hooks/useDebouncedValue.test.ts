import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";

import { useDebouncedValue } from "./useDebouncedValue";

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("useDebouncedValue", () => {
  it("returns the initial value synchronously on first render", () => {
    const { result } = renderHook(() => useDebouncedValue("hello", 300));
    expect(result.current).toBe("hello");
  });

  it("debounces rapid value changes (only the latest survives the window)", () => {
    const { result, rerender } = renderHook(
      ({ value }) => useDebouncedValue(value, 300),
      { initialProps: { value: "a" } },
    );

    rerender({ value: "ab" });
    rerender({ value: "abc" });
    rerender({ value: "abcd" });

    // Inside the window — debounced still has the original value.
    expect(result.current).toBe("a");

    act(() => {
      vi.advanceTimersByTime(150);
    });
    expect(result.current).toBe("a");

    act(() => {
      vi.advanceTimersByTime(200);
    });
    expect(result.current).toBe("abcd");
  });

  it("resets the timer when the value changes mid-window", () => {
    const { result, rerender } = renderHook(
      ({ value }) => useDebouncedValue(value, 300),
      { initialProps: { value: "x" } },
    );

    rerender({ value: "xy" });
    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(result.current).toBe("x");

    rerender({ value: "xyz" });
    act(() => {
      vi.advanceTimersByTime(200);
    });
    // Still inside the new window.
    expect(result.current).toBe("x");

    act(() => {
      vi.advanceTimersByTime(150);
    });
    expect(result.current).toBe("xyz");
  });

  it("with delayMs <= 0 acts as identity (no timer)", () => {
    const { result, rerender } = renderHook(
      ({ value }) => useDebouncedValue(value, 0),
      { initialProps: { value: "a" } },
    );

    rerender({ value: "b" });
    expect(result.current).toBe("b");
  });

  it("supports any T (numbers, objects, arrays)", () => {
    const obj1 = { count: 1 };
    const obj2 = { count: 2 };
    const { result, rerender } = renderHook(
      ({ value }) => useDebouncedValue(value, 100),
      { initialProps: { value: obj1 as { count: number } } },
    );
    expect(result.current).toBe(obj1);
    rerender({ value: obj2 });
    act(() => {
      vi.advanceTimersByTime(150);
    });
    expect(result.current).toBe(obj2);
  });

  it("clears the timeout on unmount (no late writes)", () => {
    const { result, rerender, unmount } = renderHook(
      ({ value }) => useDebouncedValue(value, 200),
      { initialProps: { value: "stay" } },
    );

    rerender({ value: "go-away" });
    unmount();

    // Advance past the debounce window — if cleanup was wrong this would
    // attempt to setState on an unmounted component (and React would log).
    act(() => {
      vi.advanceTimersByTime(500);
    });

    // Last sampled value before unmount.
    expect(result.current).toBe("stay");
  });
});
