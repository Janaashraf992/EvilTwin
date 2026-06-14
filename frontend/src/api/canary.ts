import { api } from "./client";

export interface CanaryToken {
  id: string;
  label: string;
  description: string | null;
  token_kind: string;
  difficulty: number;
  created_at: string;
  last_triggered_at: string | null;
  trigger_count: number;
  is_active: boolean;
  webhook_url: string;
}

export interface CanaryTokenListResponse {
  items: CanaryToken[];
  total: number;
}

export interface CanaryTokenCreate {
  label: string;
  description?: string;
  token_kind?: string;
  difficulty?: number;
}

export async function getCanaryTokens(): Promise<CanaryTokenListResponse> {
  const { data } = await api.get<CanaryTokenListResponse>("/canary/tokens");
  return data;
}

export async function createCanaryToken(body: CanaryTokenCreate): Promise<CanaryToken> {
  const { data } = await api.post<CanaryToken>("/canary/tokens", body);
  return data;
}

export async function deleteCanaryToken(id: string): Promise<void> {
  await api.delete(`/canary/tokens/${id}`);
}
