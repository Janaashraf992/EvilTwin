import { api } from "./client";
import type { VpnUser } from "../types";

export async function getVpnUsers(): Promise<VpnUser[]> {
  const { data } = await api.get<VpnUser[]>("/stats/vpn-users");
  return data;
}
