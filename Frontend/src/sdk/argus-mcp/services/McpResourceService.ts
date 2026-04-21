/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class McpResourceService {
  /**
   * Pending approval queue
   * Tenant-scoped pending approval requests (capped at 100). Operators should poll this resource and submit decisions via approvals.decide.
   * @returns any OK
   * @throws ApiError
   */
  public static readArgusApprovalsPending(): CancelablePromise<Record<string, any>> {
    return __request(OpenAPI, {
      method: 'GET',
      url: '/resources/approvals/pending',
      errors: {
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
      },
    });
  }
  /**
   * ARGUS signed tool catalog
   * Snapshot of the signed tool catalog (capped at 200 entries). Sandbox-internal fields (image, command_template, etc.) are stripped.
   * @returns any OK
   * @throws ApiError
   */
  public static readArgusCatalogTools(): CancelablePromise<Record<string, any>> {
    return __request(OpenAPI, {
      method: 'GET',
      url: '/resources/catalog/tools',
      errors: {
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
      },
    });
  }
  /**
   * ARGUS findings for a scan
   * Paginated findings for the given scan (tenant-scoped; capped at 200 entries).
   * @returns any OK
   * @throws ApiError
   */
  public static readArgusFindingsScan({
    scanId,
  }: {
    scanId: string,
  }): CancelablePromise<Record<string, any>> {
    return __request(OpenAPI, {
      method: 'GET',
      url: '/resources/findings/{scan_id}',
      path: {
        'scan_id': scanId,
      },
      errors: {
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
      },
    });
  }
  /**
   * ARGUS report metadata + presigned URL
   * Tenant-scoped report metadata and short-lived presigned URL. Defaults to JSON format.
   * @returns any OK
   * @throws ApiError
   */
  public static readArgusReportsReport({
    reportId,
  }: {
    reportId: string,
  }): CancelablePromise<Record<string, any>> {
    return __request(OpenAPI, {
      method: 'GET',
      url: '/resources/reports/{report_id}',
      path: {
        'report_id': reportId,
      },
      errors: {
        401: `Unauthorized (missing or invalid bearer / API key).`,
        403: `Forbidden — tenant mismatch, scope violation, or policy denial.`,
        404: `Resource not found (anti-enumeration response).`,
      },
    });
  }
}
