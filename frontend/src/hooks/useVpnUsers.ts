import { useQuery } from "@tanstack/react-query";

import { getVpnUsers } from "../api/vpnUsers";

export function useVpnUsers() {
  return useQuery({
    queryKey: ["vpn-users"],
    queryFn: getVpnUsers,
    refetchInterval: 30_000
  });
}
