/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ApprovalDecisionAction } from './ApprovalDecisionAction';
/**
 * ``approvals.decide`` arguments — operator records a decision.
 *
 * The MCP server NEVER signs approvals on the operator's behalf. The
 * ``signature_b64`` is computed externally by the operator UI from
 * ``ApprovalRequest.canonical_bytes()`` and submitted here — the MCP
 * layer only verifies and persists the resulting decision.
 */
export type ApprovalDecideInput = {
  decision: ApprovalDecisionAction;
  /**
   * Operator note attached to the decision. Required when ``decision == deny`` or ``decision == revoke``.
   */
  justification?: (string | null);
  /**
   * Operator's Ed25519 public key id (16-char hex).
   */
  public_key_id?: (string | null);
  request_id: string;
  /**
   * Required when ``decision == grant``. Ed25519 signature over ``ApprovalRequest.canonical_bytes`` produced by the operator UI.
   */
  signature_b64?: (string | null);
};

