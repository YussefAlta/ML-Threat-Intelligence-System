"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { EnrichedDocument, Stats } from "@/lib/types";
import { evaluateAlerts, type IntelligenceAlert } from "@/lib/alerts/engine";

const DISMISS_KEY = "avint_dismissed_alerts";
function loadDismissed(): Set<string> {
  if (typeof window === "undefined") return new Set();
  try {
    const raw = localStorage.getItem(DISMISS_KEY);
    if (!raw) return new Set();
    const arr = JSON.parse(raw) as string[];
    return new Set(Array.isArray(arr) ? arr : []);
  } catch {
    return new Set();
  }
}

function saveDismissed(ids: Set<string>) {
  localStorage.setItem(DISMISS_KEY, JSON.stringify(Array.from(ids)));
}

interface IntelligenceContextValue {
  stats: Stats | null;
  docs: EnrichedDocument[];
  loading: boolean;
  error: boolean;
  alerts: IntelligenceAlert[];
  dismissed: Set<string>;
  dismissAlert: (id: string) => void;
  activeAlertCount: number;
  refetch: () => void;
  notifyEnabled: boolean;
  setNotifyEnabled: (v: boolean) => void;
}

const IntelligenceContext = createContext<IntelligenceContextValue | null>(
  null,
);

const POLL_MS = 120_000;

async function fetchJson<T>(path: string): Promise<T> {
  const r = await fetch(`${path}?t=${Date.now()}`, { cache: "no-store" });
  if (!r.ok) throw new Error(String(r.status));
  return r.json() as Promise<T>;
}

export function IntelligenceProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [docs, setDocs] = useState<EnrichedDocument[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [notifyEnabled, setNotifyEnabled] = useState(false);
  const notifiedRef = useRef(new Set<string>());

  const load = useCallback(async () => {
    try {
      setError(false);
      const [statsData, enrichedData] = await Promise.all([
        fetchJson<Stats>("/data/stats.json"),
        fetchJson<EnrichedDocument[]>("/data/enriched.json"),
      ]);
      setStats(statsData);
      setDocs(Array.isArray(enrichedData) ? enrichedData : []);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setDismissed(loadDismissed());
    load();
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, [load]);

  const alerts = useMemo(() => evaluateAlerts(docs), [docs]);

  const activeAlertCount = useMemo(() => {
    return alerts.filter((a) => !dismissed.has(a.id)).length;
  }, [alerts, dismissed]);

  const dismissAlert = useCallback((id: string) => {
    setDismissed((prev) => {
      const next = new Set(prev);
      next.add(id);
      saveDismissed(next);
      return next;
    });
  }, []);

  useEffect(() => {
    if (!notifyEnabled) return;
    if (typeof Notification === "undefined") return;
    if (Notification.permission !== "granted") return;

    for (const a of alerts) {
      if (a.severity !== "critical" || dismissed.has(a.id)) continue;
      if (notifiedRef.current.has(a.id)) continue;
      notifiedRef.current.add(a.id);
      try {
        new Notification(a.title, { body: a.summary });
      } catch {
        /* ignore */
      }
    }
  }, [alerts, dismissed, notifyEnabled]);

  const value: IntelligenceContextValue = {
    stats,
    docs,
    loading,
    error,
    alerts,
    dismissed,
    dismissAlert,
    activeAlertCount,
    refetch: load,
    notifyEnabled,
    setNotifyEnabled,
  };

  return (
    <IntelligenceContext.Provider value={value}>
      {children}
    </IntelligenceContext.Provider>
  );
}

export function useIntelligence() {
  const ctx = useContext(IntelligenceContext);
  if (!ctx) {
    throw new Error("useIntelligence must be used within IntelligenceProvider");
  }
  return ctx;
}
