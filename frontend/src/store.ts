import { create } from "zustand";
import type { View } from "./types";

interface LabState {
  view: View;
  selectedCycle: string | null;
  setView: (view: View) => void;
  selectCycle: (id: string) => void;
}

export const useLabStore = create<LabState>((set) => ({
  view: "overview",
  selectedCycle: null,
  setView: (view) => set({ view }),
  selectCycle: (selectedCycle) => set({ selectedCycle })
}));
