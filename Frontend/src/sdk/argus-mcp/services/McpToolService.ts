/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ApprovalDecideResult } from '../models/ApprovalDecideResult';
import type { ApprovalListResult } from '../models/ApprovalListResult';
import type { approvals_decideArguments } from '../models/approvals_decideArguments';
import type { approvals_listArguments } from '../models/approvals_listArguments';
import type { FindingDetail } from '../models/FindingDetail';
import type { FindingListResult } from '../models/FindingListResult';
import type { FindingMarkResult } from '../models/FindingMarkResult';
import type { findings_getArguments } from '../models/findings_getArguments';
import type { findings_listArguments } from '../models/findings_listArguments';
import type { findings_mark_false_positiveArguments } from '../models/findings_mark_false_positiveArguments';
import type { policy_evaluateArguments } from '../models/policy_evaluateArguments';
import type { PolicyEvaluateResult } from '../models/PolicyEvaluateResult';
import type { report_downloadArguments } from '../models/report_downloadArguments';
import type { report_generateArguments } from '../models/report_generateArguments';
import type { ReportDownloadResult } from '../models/ReportDownloadResult';
import type { ReportGenerateResult } from '../models/ReportGenerateResult';
import type { scan_cancelArguments } from '../models/scan_cancelArguments';
import type { scan_createArguments } from '../models/scan_createArguments';
import type { scan_statusArguments } from '../models/scan_statusArguments';
import type { ScanCancelResult } from '../models/ScanCancelResult';
import type { ScanCreateResult } from '../models/ScanCreateResult';
import type { ScanStatusResult } from '../models/ScanStatusResult';
import type { scope_verifyArguments } from '../models/scope_verifyArguments';
import type { ScopeVerifyResult } from '../models/ScopeVerifyResult';
import type { tool_catalog_listArguments } from '../models/tool_catalog_listArguments';
import type { tool_run_statusArguments } from '../models/tool_run_statusArguments';
import type { tool_run_triggerArguments } from '../models/tool_run_triggerArguments';
import type { ToolCatalogListResult } from '../models/ToolCatalogListResult';
import type { ToolRunStatusResult } from '../models/ToolRunStatusResult';
import type { ToolRunTriggerResult } from '../models/ToolRunTriggerResult';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class McpToolService {
  /**
   * approvals.decide
   * Record an operator decision (grant / deny / revoke) on an approval request. The MCP server verifies signatures but never produces them: GRANT decisions require a pre-computed Ed25519 signature.
   * @returns ApprovalDecideResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callApprovalsDecide({
    requestBody,
  }: {
    requestBody: approvals_decideArguments,
  }): CancelablePromise<ApprovalDecideResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/approvals.decide',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * approvals.list
   * List approval requests visible to the authenticated tenant. Supports filtering by status (pending/granted/denied/revoked/expired) and tool_id.
   * @returns ApprovalListResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callApprovalsList({
    requestBody,
  }: {
    requestBody: approvals_listArguments,
  }): CancelablePromise<ApprovalListResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/approvals.list',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * findings.get
   * Return a single finding (with redacted evidence and proof-of-concept) owned by the authenticated tenant.
   * @returns FindingDetail OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callFindingsGet({
    requestBody,
  }: {
    requestBody: findings_getArguments,
  }): CancelablePromise<FindingDetail> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/findings.get',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * findings.list
   * List findings for a scan owned by the authenticated tenant. Supports filtering by severity, CWE, OWASP category, and confidence; returns paginated summaries.
   * @returns FindingListResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callFindingsList({
    requestBody,
  }: {
    requestBody: findings_listArguments,
  }): CancelablePromise<FindingListResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/findings.list',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * findings.mark_false_positive
   * Mark a finding as a false positive (with operator justification). Idempotent — returning ``unchanged`` when already flagged.
   * @returns FindingMarkResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callFindingsMarkFalsePositive({
    requestBody,
  }: {
    requestBody: findings_mark_false_positiveArguments,
  }): CancelablePromise<FindingMarkResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/findings.mark_false_positive',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * policy.evaluate
   * Run the PolicyEngine against a hypothetical action and return one of allowed / requires_approval / denied. Used by the LLM to pre-flight a tool call before invoking ``tool.run.trigger``.
   * @returns PolicyEvaluateResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callPolicyEvaluate({
    requestBody,
  }: {
    requestBody: policy_evaluateArguments,
  }): CancelablePromise<PolicyEvaluateResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/policy.evaluate',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * report.download
   * Return a short-lived presigned URL and SHA-256 for a report owned by the authenticated tenant. The MCP server NEVER streams artifact bytes in the JSON-RPC response.
   * @returns ReportDownloadResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callReportDownload({
    requestBody,
  }: {
    requestBody: report_downloadArguments,
  }): CancelablePromise<ReportDownloadResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/report.download',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * report.generate
   * Queue a report (Midgard / Asgard / Valhalla cascade) for a scan owned by the authenticated tenant. The MCP server only enqueues the generation job — poll ``report.download`` for the artifact.
   * @returns ReportGenerateResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callReportGenerate({
    requestBody,
  }: {
    requestBody: report_generateArguments,
  }): CancelablePromise<ReportGenerateResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/report.generate',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * scan.cancel
   * Cancel an in-progress scan owned by the authenticated tenant. Requires an operator-supplied reason that is recorded in the audit log.
   * @returns ScanCancelResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callScanCancel({
    requestBody,
  }: {
    requestBody: scan_cancelArguments,
  }): CancelablePromise<ScanCancelResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/scan.cancel',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * scan.create
   * Enqueue a new pentest scan for the authenticated tenant. Returns the new scan_id and high-level lifecycle state. DEEP profile requires a justification.
   * @returns ScanCreateResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callScanCreate({
    requestBody,
  }: {
    requestBody: scan_createArguments,
  }): CancelablePromise<ScanCreateResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/scan.create',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * scan.status
   * Return the current status, progress, and severity counts for a scan owned by the authenticated tenant.
   * @returns ScanStatusResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callScanStatus({
    requestBody,
  }: {
    requestBody: scan_statusArguments,
  }): CancelablePromise<ScanStatusResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/scan.status',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * scope.verify
   * Check whether a given target is in the authenticated tenant's customer scope. Returns the raw ScopeEngine decision plus a closed-taxonomy failure summary.
   * @returns ScopeVerifyResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callScopeVerify({
    requestBody,
  }: {
    requestBody: scope_verifyArguments,
  }): CancelablePromise<ScopeVerifyResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/scope.verify',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * tool.catalog.list
   * List tools from the signed catalog, optionally filtered by category, risk level, or approval requirement. The catalog is loaded from the process-wide signed registry (sandbox-internal fields are stripped).
   * @returns ToolCatalogListResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callToolCatalogList({
    requestBody,
  }: {
    requestBody: tool_catalog_listArguments,
  }): CancelablePromise<ToolCatalogListResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/tool.catalog.list',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * tool.run.status
   * Return the lifecycle state of an ad-hoc tool run owned by the authenticated tenant.
   * @returns ToolRunStatusResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callToolRunStatus({
    requestBody,
  }: {
    requestBody: tool_run_statusArguments,
  }): CancelablePromise<ToolRunStatusResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/tool.run.status',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
  /**
   * tool.run.trigger
   * Trigger an ad-hoc tool run for the authenticated tenant. HIGH or DESTRUCTIVE risk tools are NEVER executed inline — instead they create an approval request and return ``status=approval_pending``.
   * @returns ToolRunTriggerResult OK — tool call accepted and executed.
   * @throws ApiError
   */
  public static callToolRunTrigger({
    requestBody,
  }: {
    requestBody: tool_run_triggerArguments,
  }): CancelablePromise<ToolRunTriggerResult> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/rpc/tool.run.trigger',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
        422: `Invalid arguments — validation error.`,
        429: `Rate limit exceeded.`,
        500: `Internal MCP error (server-side stack trace redacted).`,
      },
    });
  }
}
