/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * ``tool.run.trigger(tool_id, target, params)`` arguments.
 */
export type ToolRunTriggerInput = {
  /**
   * Required when the resolved tool has ``risk_level >= high``.
   */
  justification?: (string | null);
  /**
   * Whitelisted argv overrides — keys must match the tool's allowed placeholder set (see src.sandbox.templating.ALLOWED_PLACEHOLDERS).
   */
  params?: Record<string, string>;
  scan_id?: (string | null);
  target: string;
  tool_id: string;
};

