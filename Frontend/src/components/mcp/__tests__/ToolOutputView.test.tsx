import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToolOutputView } from "../ToolOutputView";

describe("ToolOutputView", () => {
  let writeText: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    writeText = vi.fn(() => Promise.resolve());
    // navigator.clipboard is defined as a getter-only property in JSDOM
    // (since v22+), so we have to redefine it via Object.defineProperty.
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
      writable: true,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders an empty-state message when data is null", () => {
    render(<ToolOutputView data={null} />);
    expect(screen.getByTestId("mcp-tool-output-empty")).toBeInTheDocument();
  });

  it("renders an empty-state message when data is undefined", () => {
    render(<ToolOutputView data={undefined} />);
    expect(screen.getByTestId("mcp-tool-output-empty")).toBeInTheDocument();
  });

  it("renders the tree view by default for object payloads", () => {
    render(<ToolOutputView data={{ scan_id: "abc-123" }} />);
    expect(screen.getByTestId("mcp-tool-output-tree")).toBeInTheDocument();
    expect(screen.queryByTestId("mcp-tool-output-json")).toBeNull();
  });

  it("respects `defaultMode='json'`", () => {
    render(<ToolOutputView data={{ scan_id: "abc-123" }} defaultMode="json" />);
    expect(screen.getByTestId("mcp-tool-output-json")).toBeInTheDocument();
    expect(screen.queryByTestId("mcp-tool-output-tree")).toBeNull();
  });

  it("toggles between tree and JSON modes", async () => {
    const user = userEvent.setup();
    render(<ToolOutputView data={{ scan_id: "abc-123" }} />);
    await user.click(screen.getByTestId("mcp-tool-output-mode-json"));
    expect(screen.getByTestId("mcp-tool-output-json")).toBeInTheDocument();
    await user.click(screen.getByTestId("mcp-tool-output-mode-tree"));
    expect(screen.getByTestId("mcp-tool-output-tree")).toBeInTheDocument();
  });

  it("renders the optional title", () => {
    render(<ToolOutputView data={{ ok: true }} title="Run summary" />);
    expect(screen.getByText("Run summary")).toBeInTheDocument();
  });

  it("falls back to the default title when none is provided", () => {
    render(<ToolOutputView data={{ ok: true }} />);
    expect(screen.getByText("Output")).toBeInTheDocument();
  });

  it("formats JSON with 2-space indentation in JSON mode", () => {
    render(
      <ToolOutputView data={{ a: 1, b: { c: 2 } }} defaultMode="json" />,
    );
    const pre = screen.getByTestId("mcp-tool-output-json");
    expect(pre.textContent).toContain('"a": 1');
    expect(pre.textContent).toContain('"b": {');
  });

  it("copies the JSON payload to the clipboard when the copy button is clicked", async () => {
    // userEvent.setup() reinstalls its own clipboard implementation. Capture
    // it after setup, then override writeText so we can assert on the call.
    const user = userEvent.setup();
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
      writable: true,
    });
    render(<ToolOutputView data={{ scan_id: "abc-123" }} />);
    await user.click(screen.getByTestId("mcp-tool-output-copy"));
    expect(writeText).toHaveBeenCalledWith(
      JSON.stringify({ scan_id: "abc-123" }, expect.any(Function), 2),
    );
    await waitFor(() =>
      expect(screen.getByTestId("mcp-tool-output-copy")).toHaveTextContent(
        /Copied/,
      ),
    );
  });

  it("hides the copy button when `disableCopy` is true", () => {
    render(<ToolOutputView data={{ a: 1 }} disableCopy />);
    expect(screen.queryByTestId("mcp-tool-output-copy")).toBeNull();
  });

  it("wraps array payloads under an `items` root for the tree view", () => {
    render(<ToolOutputView data={[1, 2, 3]} />);
    expect(screen.getByTestId("mcp-tool-output-tree")).toBeInTheDocument();
  });

  it("does not throw on circular structures in JSON mode", () => {
    const obj: Record<string, unknown> = { name: "loop" };
    obj.self = obj;
    expect(() =>
      render(<ToolOutputView data={obj} defaultMode="json" />),
    ).not.toThrow();
    expect(screen.getByTestId("mcp-tool-output-json").textContent).toContain(
      "[Circular]",
    );
  });

  it("handles primitive values gracefully", () => {
    render(<ToolOutputView data={"plain text"} defaultMode="json" />);
    expect(screen.getByTestId("mcp-tool-output-json").textContent).toContain(
      '"plain text"',
    );
  });
});
