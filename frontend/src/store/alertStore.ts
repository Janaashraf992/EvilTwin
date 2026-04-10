import { create } from "zustand";

import type { Alert } from "../types";

type AlertStore = {
  alerts: Alert[];
  pushAlert: (alert: Alert) => void;
};

export const useAlertStore = create<AlertStore>((set) => ({
  alerts: [],
  pushAlert: (alert) =>
    set((state) => ({
      alerts: [alert, ...state.alerts].slice(0, 100)
    }))
}));
