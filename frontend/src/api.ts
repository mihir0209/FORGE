import type { Coverage, CycleDetail, CycleSummary, FraudFamily, Gap, ModelCard } from "./types";

async function get<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json() as Promise<T>;
}

export const api = {
  cycles: () => get<CycleSummary[]>("/api/cycles"),
  cycle: (id: string) => get<CycleDetail>(`/api/cycles/${id}`),
  coverage: () => get<Coverage>("/api/coverage"),
  gaps: () => get<Gap[]>("/api/gaps"),
  model: () => get<ModelCard>("/api/model"),
  families: () => get<FraudFamily[]>("/api/families"),
  chat: async (message: string, cycleId: string | null) => {
    const response = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, cycle_id: cycleId })
    });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return response.json() as Promise<{ answer: string; evidence_refs: string[]; uncertainty: string; refused: boolean }>;
  }
};
