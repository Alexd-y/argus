import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { RJSFSchema } from "@rjsf/utils";
import { ToolForm } from "../ToolForm";

const STRING_SCHEMA: RJSFSchema = {
  type: "object",
  required: ["target"],
  properties: {
    target: { type: "string", title: "Target" },
    timeout: { type: "integer", title: "Timeout (s)", default: 30 },
  },
};

const SECRET_SCHEMA: RJSFSchema = {
  type: "object",
  properties: {
    api_key: { type: "string", title: "API key" },
    bearer_token: { type: "string", title: "Bearer token" },
    description: { type: "string", title: "Description" },
  },
};

describe("ToolForm", () => {
  it("renders a labelled input for every property in the schema", () => {
    render(<ToolForm schema={STRING_SCHEMA} onSubmit={() => {}} />);
    expect(screen.getByLabelText(/Target/)).toBeInTheDocument();
    expect(screen.getByLabelText(/Timeout/)).toBeInTheDocument();
  });

  it("uses the provided submit label", () => {
    render(
      <ToolForm
        schema={STRING_SCHEMA}
        onSubmit={() => {}}
        submitLabel="Trigger nuclei"
      />,
    );
    expect(
      screen.getByRole("button", { name: /Trigger nuclei/i }),
    ).toBeInTheDocument();
  });

  it("emits onSubmit with the typed payload on a valid submission", async () => {
    const handleSubmit = vi.fn();
    const user = userEvent.setup();
    render(
      <ToolForm
        schema={STRING_SCHEMA}
        initialFormData={{ target: "https://example.com", timeout: 30 }}
        onSubmit={handleSubmit}
      />,
    );
    await user.click(screen.getByTestId("mcp-tool-form-submit"));
    expect(handleSubmit).toHaveBeenCalledTimes(1);
    expect(handleSubmit).toHaveBeenCalledWith(
      expect.objectContaining({ target: "https://example.com", timeout: 30 }),
    );
  });

  it("does NOT submit when a required field is empty", async () => {
    const handleSubmit = vi.fn();
    const user = userEvent.setup();
    render(<ToolForm schema={STRING_SCHEMA} onSubmit={handleSubmit} />);
    await user.click(screen.getByTestId("mcp-tool-form-submit"));
    expect(handleSubmit).not.toHaveBeenCalled();
  });

  it("calls onChange every time the user edits a field", async () => {
    const handleChange = vi.fn();
    const user = userEvent.setup();
    render(
      <ToolForm
        schema={STRING_SCHEMA}
        onSubmit={() => {}}
        onChange={handleChange}
      />,
    );
    await user.type(screen.getByLabelText(/Target/), "argus.io");
    expect(handleChange).toHaveBeenCalled();
    const lastCall = handleChange.mock.calls.at(-1);
    expect(lastCall?.[0]).toEqual(expect.objectContaining({ target: "argus.io" }));
  });

  it("renders password-typed widget for fields named like secrets", () => {
    render(<ToolForm schema={SECRET_SCHEMA} onSubmit={() => {}} />);
    const apiKey = screen.getByLabelText(/API key/);
    expect(apiKey).toHaveAttribute("type", "password");
    const bearer = screen.getByLabelText(/Bearer token/);
    expect(bearer).toHaveAttribute("type", "password");
  });

  it("keeps non-secret fields as regular text inputs", () => {
    render(<ToolForm schema={SECRET_SCHEMA} onSubmit={() => {}} />);
    const description = screen.getByLabelText(/Description/);
    expect(description).toHaveAttribute("type", "text");
  });

  it("disables every input when `disabled` is true", () => {
    render(
      <ToolForm
        schema={STRING_SCHEMA}
        onSubmit={() => {}}
        disabled
      />,
    );
    expect(screen.getByLabelText(/Target/)).toBeDisabled();
    expect(screen.getByLabelText(/Timeout/)).toBeDisabled();
  });

  it("shows the running label when disabled", () => {
    render(<ToolForm schema={STRING_SCHEMA} onSubmit={() => {}} disabled />);
    expect(screen.getByTestId("mcp-tool-form-submit")).toHaveTextContent(
      /Running/,
    );
  });

  it("hides the submit button when hideSubmit is true", () => {
    render(
      <ToolForm
        schema={STRING_SCHEMA}
        onSubmit={() => {}}
        hideSubmit
      />,
    );
    expect(screen.queryByTestId("mcp-tool-form-submit")).toBeNull();
  });

  it("merges user-supplied uiSchema with auto-detected secret widgets", () => {
    render(
      <ToolForm
        schema={SECRET_SCHEMA}
        onSubmit={() => {}}
        uiSchema={{
          description: { "ui:placeholder": "Describe the run" },
        }}
      />,
    );
    expect(screen.getByLabelText(/API key/)).toHaveAttribute("type", "password");
    expect(screen.getByPlaceholderText("Describe the run")).toBeInTheDocument();
  });

  it("respects an explicit `format: password` even on a non-secret field name", () => {
    render(
      <ToolForm
        schema={{
          type: "object",
          properties: {
            footer: { type: "string", title: "Footer", format: "password" },
          },
        }}
        onSubmit={() => {}}
      />,
    );
    expect(screen.getByLabelText(/Footer/)).toHaveAttribute("type", "password");
  });

  it("renders nothing dangerous when given an empty schema", () => {
    render(
      <ToolForm
        schema={{ type: "object", properties: {} }}
        onSubmit={() => {}}
      />,
    );
    expect(screen.getByTestId("mcp-tool-form")).toBeInTheDocument();
    expect(screen.getByTestId("mcp-tool-form-submit")).toBeInTheDocument();
  });
});
