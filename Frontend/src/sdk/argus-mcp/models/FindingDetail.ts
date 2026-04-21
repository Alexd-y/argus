/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Severity } from './Severity';
/**
 * Full finding payload exposed via ``findings.get``.
 *
 * Notes
 * -----
 * The ``proof_of_concept`` and ``evidence_refs`` payloads are surfaced
 * *only* after :class:`src.evidence.redaction` has scrubbed secrets — the
 * MCP server never serves raw artifacts.
 */
export type FindingDetail = {
  confidence?: string;
  created_at?: (string | null);
  cvss?: (number | null);
  cwe?: (string | null);
  description?: (string | null);
  evidence_refs?: Array<string>;
  evidence_type?: (string | null);
  false_positive?: boolean;
  false_positive_reason?: (string | null);
  finding_id: string;
  owasp_category?: (string | null);
  proof_of_concept?: (Record<string, any> | null);
  reproducible_steps?: (string | null);
  scan_id: string;
  severity: Severity;
  title: string;
};

