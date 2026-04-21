"use client";

import { useMemo } from "react";
import Form from "@rjsf/core";
import type { IChangeEvent } from "@rjsf/core";
import type { RJSFSchema, UiSchema } from "@rjsf/utils";
import validator from "@rjsf/validator-ajv8";

const SECRET_FIELD_HINTS = [
  "password",
  "secret",
  "token",
  "credential",
  "api_key",
  "apikey",
  "bearer",
];

export interface ToolFormProps<TFormData = Record<string, unknown>> {
  /** JSON Schema describing the tool's `inputSchema` (from the catalog). */
  schema: RJSFSchema;
  /** Initial form data. */
  initialFormData?: TFormData;
  /** Optional uiSchema overrides. Sensible defaults are merged in. */
  uiSchema?: UiSchema<TFormData, RJSFSchema>;
  /** Called whenever the user submits a valid form. */
  onSubmit: (formData: TFormData) => void;
  /** Optional submit-button label (defaults to "Run tool"). */
  submitLabel?: string;
  /** Disable the form (e.g. while a mutation is in flight). */
  disabled?: boolean;
  /** Called when the form data changes (useful for controlled forms). */
  onChange?: (formData: TFormData) => void;
  /** Optional id for accessibility / labelling. */
  formId?: string;
  /** When true, hide the submit button entirely (caller renders one). */
  hideSubmit?: boolean;
}

/**
 * Tool input form rendered from a JSON Schema.
 *
 * Wraps `@rjsf/core` with sane defaults for ARGUS:
 *   - Sensitive fields (`password`, `secret`, `token`, …) are auto-rendered
 *     with `type=password` to prevent accidental shoulder-surfing of bearer
 *     tokens, API keys, and credentials.
 *   - Disabled state is propagated to every widget so the form locks down
 *     while the parent mutation is in flight.
 *   - Submit-button label and visibility are configurable for two-pane
 *     layouts where the run button lives outside the form.
 */
export function ToolForm<TFormData extends Record<string, unknown> = Record<string, unknown>>({
  schema,
  initialFormData,
  uiSchema,
  onSubmit,
  submitLabel = "Run tool",
  disabled = false,
  onChange,
  formId,
  hideSubmit = false,
}: ToolFormProps<TFormData>) {
  const mergedUiSchema = useMemo<UiSchema<TFormData, RJSFSchema>>(
    () => buildUiSchema(schema, uiSchema, disabled),
    [schema, uiSchema, disabled],
  );

  const handleSubmit = (event: IChangeEvent<TFormData, RJSFSchema>) => {
    if (event.formData !== undefined) {
      onSubmit(event.formData);
    }
  };

  const handleChange = (event: IChangeEvent<TFormData, RJSFSchema>) => {
    if (onChange && event.formData !== undefined) {
      onChange(event.formData);
    }
  };

  return (
    <div data-testid="mcp-tool-form" className="mcp-tool-form">
      <Form<TFormData, RJSFSchema>
        schema={schema}
        uiSchema={mergedUiSchema}
        formData={initialFormData}
        validator={validator}
        disabled={disabled}
        readonly={disabled}
        showErrorList={false}
        liveValidate={false}
        idPrefix={formId ?? "mcp-tool-form"}
        onSubmit={handleSubmit}
        onChange={handleChange}
      >
        {hideSubmit ? (
          <></>
        ) : (
          <button
            type="submit"
            disabled={disabled}
            data-testid="mcp-tool-form-submit"
            className="mt-3 inline-flex items-center justify-center rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition hover:bg-[var(--accent-hover)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            {disabled ? "Running…" : submitLabel}
          </button>
        )}
      </Form>
    </div>
  );
}

/**
 * Build a uiSchema that:
 *   1. Auto-detects sensitive field names and switches them to `password`.
 *   2. Disables every property when `disabled === true`.
 *   3. Honours user-supplied overrides last (highest priority).
 */
function buildUiSchema<TFormData>(
  schema: RJSFSchema,
  override: UiSchema<TFormData, RJSFSchema> | undefined,
  disabled: boolean,
): UiSchema<TFormData, RJSFSchema> {
  const baseUi: UiSchema<TFormData, RJSFSchema> = {
    "ui:submitButtonOptions": { norender: true },
  };

  if (schema.type === "object" && schema.properties) {
    for (const [name, prop] of Object.entries(schema.properties)) {
      if (typeof prop !== "object" || prop === null) {
        continue;
      }
      const fieldUi: Record<string, unknown> = {};
      if (isSecretField(name, prop as RJSFSchema)) {
        fieldUi["ui:widget"] = "password";
        fieldUi["ui:options"] = { autocomplete: "off" };
      }
      if (disabled) {
        fieldUi["ui:disabled"] = true;
      }
      if (Object.keys(fieldUi).length > 0) {
        (baseUi as Record<string, unknown>)[name] = fieldUi;
      }
    }
  }

  if (override) {
    return mergeUiSchemas(baseUi, override);
  }
  return baseUi;
}

function isSecretField(name: string, schema: RJSFSchema): boolean {
  if (schema.format === "password") {
    return true;
  }
  const lower = name.toLowerCase();
  return SECRET_FIELD_HINTS.some((hint) => lower.includes(hint));
}

function mergeUiSchemas<TFormData>(
  base: UiSchema<TFormData, RJSFSchema>,
  override: UiSchema<TFormData, RJSFSchema>,
): UiSchema<TFormData, RJSFSchema> {
  const merged: UiSchema<TFormData, RJSFSchema> = { ...base };
  for (const [key, value] of Object.entries(override)) {
    const existing = (merged as Record<string, unknown>)[key];
    if (
      existing &&
      typeof existing === "object" &&
      !Array.isArray(existing) &&
      value &&
      typeof value === "object" &&
      !Array.isArray(value)
    ) {
      (merged as Record<string, unknown>)[key] = {
        ...(existing as Record<string, unknown>),
        ...(value as Record<string, unknown>),
      };
    } else {
      (merged as Record<string, unknown>)[key] = value;
    }
  }
  return merged;
}
