import { api } from "./client";
import type { DashboardStats } from "../types";
import { MOCK_STATS } from "./mockData";

const SHOWCASE_MODE = import.meta.env.VITE_SHOWCASE_MODE === 'true';

export async function getStats(): Promise<DashboardStats> {
  if (SHOWCASE_MODE) {
    return new Promise((resolve) => setTimeout(() => resolve(MOCK_STATS), 300));
  }
  const { data } = await api.get<DashboardStats>("/stats");
  return data;
}
