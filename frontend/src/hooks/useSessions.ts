import { useQuery } from "@tanstack/react-query";

import { getSession, getSessions, type SessionFilters } from "../api/sessions";

export function useSessions(filters: SessionFilters) {
  return useQuery({
    queryKey: ["sessions", filters],
    queryFn: () => getSessions(filters)
  });
}

export function useSession(id: string | null) {
  return useQuery({
    queryKey: ["session", id],
    queryFn: () => getSession(id as string),
    enabled: Boolean(id)
  });
}
