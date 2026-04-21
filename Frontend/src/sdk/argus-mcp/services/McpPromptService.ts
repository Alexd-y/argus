/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RemediationAdvisorPromptArguments } from '../models/RemediationAdvisorPromptArguments';
import type { SeverityNormalizerPromptArguments } from '../models/SeverityNormalizerPromptArguments';
import type { VulnerabilityExplainerPromptArguments } from '../models/VulnerabilityExplainerPromptArguments';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class McpPromptService {
  /**
   * Propose safe-by-default remediation steps for a finding
   * Generates step-by-step remediation guidance for a finding. Inputs: title, severity, stack hint (optional), evidence summary.
   * @returns any Rendered prompt as a list of MCP messages.
   * @throws ApiError
   */
  public static renderRemediationAdvisor({
    requestBody,
  }: {
    requestBody: RemediationAdvisorPromptArguments,
  }): CancelablePromise<Record<string, any>> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/prompts/remediation.advisor',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
      },
    });
  }
  /**
   * Normalize advisory severity to CVSS-3.1 + OWASP Top-10
   * Maps an unstructured advisory to ARGUS-canonical severity, CVSS-3.1 vector, and OWASP 2025 Top-10 category.
   * @returns any Rendered prompt as a list of MCP messages.
   * @throws ApiError
   */
  public static renderSeverityNormalizer({
    requestBody,
  }: {
    requestBody: SeverityNormalizerPromptArguments,
  }): CancelablePromise<Record<string, any>> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/prompts/severity.normalizer',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
      },
    });
  }
  /**
   * Explain a finding to a non-security audience
   * Produce a stakeholder-friendly explanation of a single finding. Inputs: title, severity, optional CWE / OWASP / description.
   * @returns any Rendered prompt as a list of MCP messages.
   * @throws ApiError
   */
  public static renderVulnerabilityExplainer({
    requestBody,
  }: {
    requestBody: VulnerabilityExplainerPromptArguments,
  }): CancelablePromise<Record<string, any>> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/prompts/vulnerability.explainer',
      body: requestBody,
      mediaType: 'application/json',
      errors: {
        400: `Invalid arguments — validation error.`,
        401: `Unauthorized (missing or invalid bearer / API key).`,
      },
    });
  }
}
