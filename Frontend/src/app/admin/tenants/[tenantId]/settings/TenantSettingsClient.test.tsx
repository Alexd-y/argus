/**
 * B6-T02 / T48 — TenantSettingsClient PDF archival format selector tests.
 *
 * Coverage matrix:
 *
 *   - Section renders with both options + correct localised labels.
 *   - Initial radio reflects the tenant's stored ``pdf_archival_format``.
 *   - Selecting a *different* value calls ``updateTenant`` with the new
 *     value and refreshes the route on success.
 *   - Selecting the *same* value is a no-op (no PATCH call).
 *   - On PATCH failure, the radio is rolled back to the previous value
 *     and the error banner surfaces a sanitised message (no stack frames).
 *   - The fieldset is disabled while the transition is pending.
 *
 * Architecture note
 * -----------------
 * ``TenantSettingsClient`` is wrapped in ``AdminRouteGuard`` which depends
 * on the role hydrated from ``sessionStorage`` by ``AdminAuthProvider``.
 * We follow the same pattern as ``AdminFindingsClient.test.tsx``:
 *
 *   1. Set the role via ``sessionStorage`` *before* render.
 *   2. Wrap the component in ``<AdminAuthProvider>``.
 *   3. ``waitFor`` until the gate hydrates (``status: "ready"``) and the
 *      child surface paints — ``data-testid="pdf-archival-format-fieldset"``
 *      is the canonical sentinel.
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const router = {
  replace: vi.fn(),
  push: vi.fn(),
  back: vi.fn(),
  forward: vi.fn(),
  refresh: vi.fn(),
  prefetch: vi.fn(),
};

vi.mock("next/navigation", () => ({
  useRouter: () => router,
}));

const updateTenant = vi.fn();
vi.mock("@/app/admin/tenants/actions", () => ({
  updateTenant: (...args: unknown[]) => updateTenant(...args),
}));

import { AdminAuthProvider } from "@/services/admin/AdminAuthContext";
import type { AdminRole } from "@/services/admin/adminRoles";
import type { AdminTenant } from "@/app/admin/tenants/actions";
import {
  PDF_ARCHIVAL_FORMAT_LABELS,
  type PdfArchivalFormat,
} from "@/app/admin/tenants/types";
import { TenantSettingsClient } from "./TenantSettingsClient";

const TENANT_ID = "00000000-0000-0000-0000-000000000099";

function makeTenant(over: Partial<AdminTenant> = {}): AdminTenant {
  return {
    id: over.id ?? TENANT_ID,
    name: over.name ?? "Acme Corp",
    exports_sarif_junit_enabled: over.exports_sarif_junit_enabled ?? false,
    rate_limit_rpm: over.rate_limit_rpm ?? null,
    scope_blacklist: over.scope_blacklist ?? null,
    retention_days: over.retention_days ?? null,
    pdf_archival_format: over.pdf_archival_format ?? "standard",
    created_at: over.created_at ?? "2026-04-01T00:00:00Z",
    updated_at: over.updated_at ?? "2026-04-01T00:00:00Z",
  };
}

function setRole(role: AdminRole) {
  window.sessionStorage.setItem("argus.admin.role", role);
}

function renderClient(initial: AdminTenant) {
  return render(
    <AdminAuthProvider>
      <TenantSettingsClient tenantId={TENANT_ID} initial={initial} />
    </AdminAuthProvider>,
  );
}

beforeEach(() => {
  router.refresh.mockReset();
  router.replace.mockReset();
  router.push.mockReset();
  updateTenant.mockReset();
});

afterEach(() => {
  window.sessionStorage.clear();
  if (typeof document !== "undefined") {
    document.cookie =
      "argus.admin.role=; path=/; max-age=0; SameSite=Strict";
  }
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Initial render
// ---------------------------------------------------------------------------

describe("TenantSettingsClient — PDF archival format section", () => {
  it("renders the fieldset with both options and localised labels", async () => {
    setRole("admin");
    renderClient(makeTenant({ pdf_archival_format: "standard" }));

    const section = await screen.findByTestId(
      "pdf-archival-format-section",
    );
    expect(section).toBeInTheDocument();

    const standard = await screen.findByTestId(
      "pdf-archival-format-option-standard",
    );
    const pdfa = await screen.findByTestId(
      "pdf-archival-format-option-pdfa-2u",
    );
    expect(standard).toBeInTheDocument();
    expect(pdfa).toBeInTheDocument();

    expect(standard).toHaveTextContent(
      PDF_ARCHIVAL_FORMAT_LABELS["standard"].en,
    );
    expect(standard).toHaveTextContent(
      PDF_ARCHIVAL_FORMAT_LABELS["standard"].ru,
    );
    expect(pdfa).toHaveTextContent(
      PDF_ARCHIVAL_FORMAT_LABELS["pdfa-2u"].en,
    );
    expect(pdfa).toHaveTextContent(
      PDF_ARCHIVAL_FORMAT_LABELS["pdfa-2u"].ru,
    );
  });

  it("preselects 'standard' when the tenant stores 'standard'", async () => {
    setRole("admin");
    renderClient(makeTenant({ pdf_archival_format: "standard" }));

    const standardRadio = await screen.findByRole("radio", {
      name: new RegExp(PDF_ARCHIVAL_FORMAT_LABELS["standard"].en, "i"),
    });
    const pdfaRadio = await screen.findByRole("radio", {
      name: new RegExp("PDF/A-2u", "i"),
    });
    expect((standardRadio as HTMLInputElement).checked).toBe(true);
    expect((pdfaRadio as HTMLInputElement).checked).toBe(false);
  });

  it("preselects 'pdfa-2u' when the tenant stores 'pdfa-2u'", async () => {
    setRole("admin");
    renderClient(makeTenant({ pdf_archival_format: "pdfa-2u" }));

    const standardRadio = await screen.findByRole("radio", {
      name: new RegExp(PDF_ARCHIVAL_FORMAT_LABELS["standard"].en, "i"),
    });
    const pdfaRadio = await screen.findByRole("radio", {
      name: new RegExp("PDF/A-2u", "i"),
    });
    expect((pdfaRadio as HTMLInputElement).checked).toBe(true);
    expect((standardRadio as HTMLInputElement).checked).toBe(false);
  });

  it("normalises an unknown server-stored value back to 'standard'", async () => {
    setRole("admin");
    renderClient(
      makeTenant({
        pdf_archival_format: "legacy-format" as unknown as PdfArchivalFormat,
      }),
    );

    const standardRadio = await screen.findByRole("radio", {
      name: new RegExp(PDF_ARCHIVAL_FORMAT_LABELS["standard"].en, "i"),
    });
    expect((standardRadio as HTMLInputElement).checked).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PATCH wiring — selecting a new value
// ---------------------------------------------------------------------------

describe("TenantSettingsClient — savePdfArchivalFormat", () => {
  it("selecting 'pdfa-2u' calls updateTenant with the new value and refreshes", async () => {
    setRole("admin");
    const updated = makeTenant({ pdf_archival_format: "pdfa-2u" });
    updateTenant.mockResolvedValue(updated);

    renderClient(makeTenant({ pdf_archival_format: "standard" }));

    const user = userEvent.setup();
    const pdfaRadio = await screen.findByRole("radio", {
      name: new RegExp("PDF/A-2u", "i"),
    });
    await user.click(pdfaRadio);

    await waitFor(() => expect(updateTenant).toHaveBeenCalledTimes(1));
    expect(updateTenant).toHaveBeenCalledWith(TENANT_ID, {
      pdf_archival_format: "pdfa-2u",
    });

    const successBanner = await screen.findByRole("status");
    expect(successBanner).toHaveTextContent(/PDF archival format saved/i);
    expect(successBanner).toHaveTextContent(/PDF\/A-2u/);

    await waitFor(() => expect(router.refresh).toHaveBeenCalledTimes(1));
  });

  it("selecting the SAME value is a no-op (no PATCH call)", async () => {
    setRole("admin");
    renderClient(makeTenant({ pdf_archival_format: "standard" }));

    const standardRadio = await screen.findByRole("radio", {
      name: new RegExp(PDF_ARCHIVAL_FORMAT_LABELS["standard"].en, "i"),
    });
    expect((standardRadio as HTMLInputElement).checked).toBe(true);

    const user = userEvent.setup();
    await user.click(standardRadio);

    await new Promise((r) => setTimeout(r, 30));
    expect(updateTenant).not.toHaveBeenCalled();
    expect(router.refresh).not.toHaveBeenCalled();
  });

  it("rolls back the radio and surfaces a sanitised error when PATCH rejects", async () => {
    setRole("admin");
    updateTenant.mockRejectedValue(
      new Error("ECONNRESET at /tmp/secret/path/to/leak.tsx:42:1"),
    );

    renderClient(makeTenant({ pdf_archival_format: "standard" }));

    const user = userEvent.setup();
    const pdfaRadio = await screen.findByRole("radio", {
      name: new RegExp("PDF/A-2u", "i"),
    });
    const standardRadio = await screen.findByRole("radio", {
      name: new RegExp(PDF_ARCHIVAL_FORMAT_LABELS["standard"].en, "i"),
    });
    await user.click(pdfaRadio);

    const errorBanner = await screen.findByRole("alert");
    expect(errorBanner).toBeInTheDocument();
    const errText = errorBanner.textContent ?? "";
    expect(errText).not.toMatch(/\.tsx|stack|at \//i);
    expect(errText).not.toMatch(/ECONNRESET/);
    expect(errText).not.toMatch(/secret/);

    await waitFor(() =>
      expect((standardRadio as HTMLInputElement).checked).toBe(true),
    );
    expect((pdfaRadio as HTMLInputElement).checked).toBe(false);

    expect(router.refresh).not.toHaveBeenCalled();
  });

  it("disables the fieldset while a transition is pending", async () => {
    setRole("admin");
    let resolveUpdate: (value: AdminTenant) => void = () => {};
    updateTenant.mockImplementation(
      () =>
        new Promise<AdminTenant>((resolve) => {
          resolveUpdate = resolve;
        }),
    );

    renderClient(makeTenant({ pdf_archival_format: "standard" }));

    const user = userEvent.setup();
    const pdfaRadio = await screen.findByRole("radio", {
      name: new RegExp("PDF/A-2u", "i"),
    });
    await user.click(pdfaRadio);

    const fieldset = await screen.findByTestId(
      "pdf-archival-format-fieldset",
    );
    await waitFor(() =>
      expect((fieldset as HTMLFieldSetElement).disabled).toBe(true),
    );

    resolveUpdate(makeTenant({ pdf_archival_format: "pdfa-2u" }));

    await waitFor(() =>
      expect((fieldset as HTMLFieldSetElement).disabled).toBe(false),
    );
  });
});
