/** Cairn blackboard API client — /api/v1/cairn/* (tenant-scoped via fetchV1). */

import { fetchV1 } from "./scanApi";

export type CairnReason = {
  worker: string;
  trigger: string | null;
  started_at: string | null;
  last_heartbeat_at: string | null;
};

export type CairnProjectMeta = {
  id: string;
  ref: string;
  title: string;
  status: "active" | "stopped" | "completed";
  bootstrap_enabled: boolean;
  created_at: string;
  reason: CairnReason | null;
  scan_id: string | null;
  execution_mode: string | null;
};

export type CairnProjectSummary = CairnProjectMeta & {
  fact_count: number;
  intent_count: number;
  working_intent_count: number;
  unclaimed_intent_count: number;
  hint_count: number;
};

export type CairnFact = {
  id: string;
  description: string;
  uuid?: string | null;
  evidence_refs?: unknown[] | null;
  evidence_tier?: number | null;
  finding_id?: string | null;
};

export type CairnIntent = {
  id: string;
  from: string[];
  to: string | null;
  description: string;
  creator: string;
  worker: string | null;
  last_heartbeat_at: string | null;
  created_at: string;
  concluded_at: string | null;
  uuid?: string | null;
};

export type CairnHint = {
  id: string;
  content: string;
  creator: string;
  created_at: string;
  uuid?: string | null;
};

export type CairnProjectDetail = {
  project: CairnProjectMeta;
  facts: CairnFact[];
  intents: CairnIntent[];
  hints: CairnHint[];
};

export type CreateProjectBody = {
  title: string;
  origin: string;
  goal: string;
  bootstrap_enabled?: boolean;
};

export const cairnApi = {
  listProjects: (status?: string) =>
    fetchV1<CairnProjectSummary[]>(`/cairn/projects${status ? `?status=${status}` : ""}`),

  getProject: (projectId: string) =>
    fetchV1<CairnProjectDetail>(`/cairn/projects/${projectId}`),

  createProject: (body: CreateProjectBody) =>
    fetchV1<CairnProjectDetail>("/cairn/projects", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  deleteProject: (projectId: string) =>
    fetchV1<void>(`/cairn/projects/${projectId}`, { method: "DELETE" }),

  updateStatus: (projectId: string, status: "active" | "stopped") =>
    fetchV1<CairnProjectMeta>(`/cairn/projects/${projectId}/status`, {
      method: "PUT",
      body: JSON.stringify({ status }),
    }),

  reopen: (projectId: string, description: string, creator: string) =>
    fetchV1<{ project: CairnProjectMeta }>(`/cairn/projects/${projectId}/reopen`, {
      method: "POST",
      body: JSON.stringify({ description, creator }),
    }),

  addHint: (projectId: string, content: string, creator: string) =>
    fetchV1<CairnHint>(`/cairn/projects/${projectId}/hints`, {
      method: "POST",
      body: JSON.stringify({ content, creator }),
    }),
};
