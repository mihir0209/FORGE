import type { Coverage, CycleDetail, CycleSummary, FraudFamily, Gap, ModelCard, Operations, PendingVariant, StrategyRepository } from "./types";

async function get<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json() as Promise<T>;
}

async function post<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: window.localStorage.getItem("forgeOperatorToken")
      ? { "X-Forge-Operator": window.localStorage.getItem("forgeOperatorToken")! }
      : undefined,
  });
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
  operations: () => get<Operations>("/api/operations"),
  variants: () => get<PendingVariant[]>("/api/variants"),
  strategies: (query = "", offset = 0, limit = 25) => get<StrategyRepository>(`/api/strategies?limit=${limit}&offset=${offset}&query=${encodeURIComponent(query)}`),
  runDemo: () => post<{ event_ids: string[]; scenarios: Array<{ seed: number; family_slug: string }>; families: string[] }>("/api/demo"),
  probeWorkers: () => post<{ event_ids: string[]; requested: number }>("/api/workers/probe"),
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
