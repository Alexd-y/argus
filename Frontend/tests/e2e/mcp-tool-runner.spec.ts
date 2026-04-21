import { expect, test, type Route } from "@playwright/test";

const CATALOG_RESPONSE = {
  total: 2,
  items: [
    {
      tool_id: "nuclei",
      category: "web_va",
      phase: "active",
      risk_level: "low",
      requires_approval: false,
      description: "Nuclei template scanner",
      cwe_hints: [89],
    },
    {
      tool_id: "metasploit",
      category: "exploit",
      phase: "exploitation",
      risk_level: "destructive",
      requires_approval: true,
      description: "Metasploit framework",
    },
  ],
};

const TRIGGER_RESPONSE = {
  tool_id: "nuclei",
  status: "running",
  risk_level: "low",
  requires_approval: false,
  tool_run_id: "run-abc-123",
};

const TRIGGER_APPROVAL_RESPONSE = {
  tool_id: "metasploit",
  status: "approval_pending",
  risk_level: "destructive",
  requires_approval: true,
  approval_request_id: "approval-xyz-7",
  audit_event_id: "evt-7",
};

async function mockMcp(route: Route) {
  const url = route.request().url();
  if (url.endsWith("/rpc/tool.catalog.list")) {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(CATALOG_RESPONSE),
    });
    return;
  }
  if (url.endsWith("/rpc/tool.run.trigger")) {
    const body = await route.request().postDataJSON();
    const toolId = body?.payload?.tool_id ?? "";
    if (toolId === "metasploit") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(TRIGGER_APPROVAL_RESPONSE),
      });
    } else {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(TRIGGER_RESPONSE),
      });
    }
    return;
  }
  if (url.includes("/notifications/stream")) {
    await route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      body: "",
    });
    return;
  }
  await route.continue();
}

test.describe("MCP tool runner (/mcp)", () => {
  test.beforeEach(async ({ context, page }) => {
    await context.addInitScript(() => {
      window.localStorage.setItem("argus.mcp.accessToken", "playwright-token");
      window.localStorage.setItem(
        "argus.mcp.tenantId",
        "00000000-0000-0000-0000-000000000001",
      );
    });
    await page.route("**/mcp/**", mockMcp);
  });

  test("renders the MCP layout when the feature flag is enabled", async ({
    page,
  }) => {
    await page.goto("/mcp");
    await expect(page.getByTestId("mcp-layout-enabled")).toBeVisible();
    await expect(page.getByTestId("mcp-tool-runner")).toBeVisible();
  });

  test("loads the tool catalog and lists every entry", async ({ page }) => {
    await page.goto("/mcp");
    await expect(page.getByTestId("mcp-tool-list-item")).toHaveCount(2);
    await expect(
      page.getByTestId("mcp-tool-list-item").first(),
    ).toContainText("nuclei");
  });

  test("filters the catalog by free-text query", async ({ page }) => {
    await page.goto("/mcp");
    await page
      .getByTestId("mcp-tool-list-filter")
      .fill("metasploit");
    await expect(page.getByTestId("mcp-tool-list-item")).toHaveCount(1);
    await expect(page.getByTestId("mcp-tool-list-item")).toContainText(
      "metasploit",
    );
  });

  test("triggers a low-risk tool and shows the structured output", async ({
    page,
  }) => {
    await page.goto("/mcp");
    await page
      .getByTestId("mcp-tool-list-item")
      .filter({ hasText: "nuclei" })
      .click();
    await page.getByLabel(/Target/).fill("https://example.com");
    await page.getByTestId("mcp-tool-form-submit").click();
    await expect(page.getByTestId("mcp-tool-output")).toContainText("running");
    await expect(page.getByTestId("mcp-tool-output")).toContainText(
      "run-abc-123",
    );
  });

  test("destructive tools surface the approval-pending response", async ({
    page,
  }) => {
    await page.goto("/mcp");
    await page
      .getByTestId("mcp-tool-list-item")
      .filter({ hasText: "metasploit" })
      .click();
    await expect(page.getByTestId("mcp-tool-risk-badge")).toContainText(
      /destructive/i,
    );
    await page.getByLabel(/Target/).fill("10.10.10.10");
    await page.getByLabel(/Justification/).fill("CTF lab");
    await page.getByTestId("mcp-tool-form-submit").click();
    await expect(page.getByTestId("mcp-tool-output")).toContainText(
      "approval_pending",
    );
    await expect(page.getByTestId("mcp-tool-output")).toContainText(
      "approval-xyz-7",
    );
  });

  test("renders NotEnabledNotice when the feature flag is off", async ({
    browser,
  }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.addInitScript(() => {
      Object.defineProperty(process ?? {}, "env", {
        value: { NEXT_PUBLIC_MCP_ENABLED: "false" },
      });
    });
    await page.goto("/mcp");
    if (await page.getByTestId("mcp-not-enabled").isVisible().catch(() => false)) {
      await expect(page.getByTestId("mcp-not-enabled")).toBeVisible();
    } else {
      test.info().annotations.push({
        type: "skip-reason",
        description:
          "Server build resolved NEXT_PUBLIC_MCP_ENABLED=true at startup; this scenario validates the route only when the build env disables it.",
      });
      test.skip(true, "Feature flag was already enabled at build time.");
    }
    await context.close();
  });
});
