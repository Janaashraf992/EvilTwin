import { api } from "./client";
import type { SessionListResponse, SessionLog } from "../types";
import { MOCK_SESSIONS } from "./mockData";

export type SessionFilters = {
  page: number;
  page_size: number;
  threat_level?: number;
  honeypot?: string;
  date_from?: string;
  date_to?: string;
  ip?: string;
};

const SHOWCASE_MODE = import.meta.env.VITE_SHOWCASE_MODE === 'true';

export async function getSessions(filters: SessionFilters): Promise<SessionListResponse> {
  if (SHOWCASE_MODE) {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          items: MOCK_SESSIONS.slice((filters.page - 1) * filters.page_size, filters.page * filters.page_size),
          total: MOCK_SESSIONS.length,
          page: filters.page,
          pages: Math.ceil(MOCK_SESSIONS.length / filters.page_size)
        });
      }, 300);
    });
  }
  const { data } = await api.get<SessionListResponse>("/sessions", { params: filters });
  return data;
}

export async function getSession(id: string): Promise<SessionLog> {
  if (SHOWCASE_MODE) {
    return new Promise((resolve, reject) => {
      const session = MOCK_SESSIONS.find(s => s.id === id);
      if (session) resolve(session);
      else reject(new Error("Session not found"));
    });
  }
  const { data } = await api.get<SessionLog>(`/sessions/${id}`);
  return data;
}
