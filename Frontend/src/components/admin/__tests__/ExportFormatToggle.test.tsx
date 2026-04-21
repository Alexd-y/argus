import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ExportFormatToggle } from "../ExportFormatToggle";
import { EXPORT_FORMAT_STORAGE_KEY } from "@/lib/findingsExport";

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
  window.localStorage.clear();
});

describe("ExportFormatToggle", () => {
  it("renders both format options with SARIF as default", async () => {
    render(<ExportFormatToggle scanId="scan-1" onDownload={vi.fn()} />);

    const sarif = screen.getByTestId("export-format-sarif");
    const junit = screen.getByTestId("export-format-junit");
    expect(sarif).toBeInTheDocument();
    expect(junit).toBeInTheDocument();

    // After mount: localStorage is empty so SARIF stays the default.
    await waitFor(() => {
      expect(sarif).toBeChecked();
    });
    expect(sarif).toHaveAttribute("aria-checked", "true");
    expect(junit).toHaveAttribute("aria-checked", "false");

    // Tooltips for both formats are present and linked via aria-describedby.
    expect(screen.getByTestId("export-format-sarif-tip")).toHaveTextContent(
      /DevSecOps/i,
    );
    expect(screen.getByTestId("export-format-junit-tip")).toHaveTextContent(
      /CI\/CD/i,
    );
    expect(sarif).toHaveAttribute(
      "aria-describedby",
      screen.getByTestId("export-format-sarif-tip").id,
    );

    // Download button starts off labelled with the default format.
    expect(screen.getByTestId("export-format-download")).toHaveTextContent(
      /Скачать SARIF/,
    );
  });

  it("selecting JUnit updates aria-checked and persists to localStorage", async () => {
    const user = userEvent.setup();
    render(<ExportFormatToggle scanId="scan-1" onDownload={vi.fn()} />);

    const junit = screen.getByTestId("export-format-junit");
    await user.click(junit);

    expect(junit).toBeChecked();
    expect(junit).toHaveAttribute("aria-checked", "true");
    expect(screen.getByTestId("export-format-sarif")).toHaveAttribute(
      "aria-checked",
      "false",
    );
    expect(window.localStorage.getItem(EXPORT_FORMAT_STORAGE_KEY)).toBe("junit");
    expect(screen.getByTestId("export-format-download")).toHaveTextContent(
      /Скачать JUnit XML/,
    );
  });

  it("download button calls API client with the selected format", async () => {
    const user = userEvent.setup();
    const onDownload = vi.fn().mockResolvedValue(undefined);
    render(<ExportFormatToggle scanId="scan-42" onDownload={onDownload} />);

    // Default SARIF → click → callback receives "sarif".
    await user.click(screen.getByTestId("export-format-download"));
    await waitFor(() => {
      expect(onDownload).toHaveBeenCalledTimes(1);
    });
    expect(onDownload).toHaveBeenLastCalledWith("sarif");

    // Switch to JUnit → click again → callback receives "junit".
    await user.click(screen.getByTestId("export-format-junit"));
    await user.click(screen.getByTestId("export-format-download"));
    await waitFor(() => {
      expect(onDownload).toHaveBeenCalledTimes(2);
    });
    expect(onDownload).toHaveBeenLastCalledWith("junit");
  });

  it("restores format from localStorage on mount", async () => {
    window.localStorage.setItem(EXPORT_FORMAT_STORAGE_KEY, "junit");
    render(<ExportFormatToggle scanId="scan-1" onDownload={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByTestId("export-format-junit")).toBeChecked();
    });
    expect(screen.getByTestId("export-format-sarif")).not.toBeChecked();
    expect(screen.getByTestId("export-format-download")).toHaveTextContent(
      /Скачать JUnit XML/,
    );
  });

  it("falls back to SARIF when localStorage value is invalid", async () => {
    window.localStorage.setItem(EXPORT_FORMAT_STORAGE_KEY, "xml-pwn");
    render(<ExportFormatToggle scanId="scan-1" onDownload={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByTestId("export-format-sarif")).toBeChecked();
    });
    expect(screen.getByTestId("export-format-junit")).not.toBeChecked();
  });

  it("disables the download button while a request is in flight", async () => {
    const user = userEvent.setup();
    let resolveDownload: () => void = () => undefined;
    const onDownload = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveDownload = resolve;
        }),
    );
    render(<ExportFormatToggle scanId="scan-1" onDownload={onDownload} />);
    const button = screen.getByTestId("export-format-download");

    await user.click(button);
    await waitFor(() => {
      expect(button).toBeDisabled();
      expect(button).toHaveTextContent(/Скачивание/);
    });

    resolveDownload();
    await waitFor(() => {
      expect(button).not.toBeDisabled();
    });
  });

  it("renders an inline error message when the download throws (no stack leak)", async () => {
    const user = userEvent.setup();
    const onDownload = vi.fn().mockRejectedValue(
      new Error("Error: connect ECONNREFUSED 127.0.0.1:8000\n    at TCPConnect.onConnect"),
    );
    render(<ExportFormatToggle scanId="scan-1" onDownload={onDownload} />);

    await user.click(screen.getByTestId("export-format-download"));

    const error = await screen.findByTestId("export-format-error");
    expect(error).toHaveAttribute("role", "alert");
    expect(error.textContent ?? "").not.toMatch(/ECONNREFUSED/);
    expect(error.textContent ?? "").not.toMatch(/at TCPConnect/);
  });

  it("disables the download button when scanId is blank", () => {
    render(<ExportFormatToggle scanId="   " onDownload={vi.fn()} />);
    expect(screen.getByTestId("export-format-download")).toBeDisabled();
  });

  it("exposes a single accessible radiogroup with two named radios", () => {
    render(<ExportFormatToggle scanId="scan-1" onDownload={vi.fn()} />);
    const group = screen.getByRole("radiogroup", { name: /формат экспорта/i });
    expect(group).toBeInTheDocument();
    const radios = screen.getAllByRole("radio");
    expect(radios).toHaveLength(2);
  });
});
