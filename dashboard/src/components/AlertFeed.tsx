"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { Bell, BellOff, X, ShieldAlert } from "lucide-react";
import { useIntelligence } from "@/context/IntelligenceContext";
import { ALERT_RULES } from "@/lib/alerts/rules";
import type { IntelligenceAlert } from "@/lib/alerts/engine";

const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/35",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/35",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/35",
};

function AlertRow({
  alert,
  onDismiss,
}: {
  alert: IntelligenceAlert;
  onDismiss: (id: string) => void;
}) {
  return (
    <div className="flex items-start gap-3 py-3 border-b border-slate-700/40 last:border-0">
      <ShieldAlert className="w-4 h-4 text-cyan-500 shrink-0 mt-0.5" />
      <div className="flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2 mb-1">
          <span
            className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${SEV_BADGE[alert.severity] ?? "bg-slate-700"}`}
          >
            {alert.severity}
          </span>
          <span className="text-xs font-medium text-slate-200">{alert.title}</span>
        </div>
        <p className="text-sm text-slate-400 line-clamp-2">{alert.summary}</p>
        <div className="flex items-center gap-3 mt-2">
          <Link
            href={`/threats/${encodeURIComponent(alert.docId)}`}
            className="text-xs text-cyan-400 hover:text-cyan-300"
          >
            View threat
          </Link>
          <button
            type="button"
            onClick={() => onDismiss(alert.id)}
            className="text-xs text-slate-500 hover:text-slate-300 flex items-center gap-1"
          >
            <X className="w-3 h-3" /> Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}

interface AlertFeedProps {
  compact?: boolean;
  maxItems?: number;
}

export function AlertFeed({ compact = false, maxItems = 12 }: AlertFeedProps) {
  const {
    alerts,
    dismissed,
    dismissAlert,
    notifyEnabled,
    setNotifyEnabled,
    docs,
    loading,
  } = useIntelligence();
  const [ruleFilter, setRuleFilter] = useState<string>("");

  const active = useMemo(() => {
    let list = alerts.filter((a) => !dismissed.has(a.id));
    if (ruleFilter) list = list.filter((a) => a.ruleId === ruleFilter);
    return list.slice(0, maxItems);
  }, [alerts, dismissed, ruleFilter, maxItems]);

  async function requestNotify() {
    if (typeof Notification === "undefined") return;
    const p = await Notification.requestPermission();
    setNotifyEnabled(p === "granted");
  }

  if (loading && !docs.length) {
    return (
      <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-8 text-center text-slate-500 text-sm">
        Loading alerts…
      </div>
    );
  }

  return (
    <div
      className={`bg-slate-800/50 rounded-xl border border-slate-700/40 ${compact ? "p-4" : "p-5"}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <Bell className="w-4 h-4 text-amber-400" />
            Alert feed
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Rule-based signals on loaded intelligence ({docs.length.toLocaleString()} docs)
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={ruleFilter}
            onChange={(e) => setRuleFilter(e.target.value)}
            className="bg-slate-900 border border-slate-600 rounded-lg text-xs text-slate-200 px-2 py-1.5"
          >
            <option value="">All rules</option>
            {ALERT_RULES.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
          {typeof Notification !== "undefined" && (
            <button
              type="button"
              onClick={() =>
                notifyEnabled ? setNotifyEnabled(false) : requestNotify()
              }
              className="flex items-center gap-1.5 text-xs px-2 py-1.5 rounded-lg border border-slate-600 text-slate-300 hover:bg-slate-800"
            >
              {notifyEnabled ? (
                <>
                  <BellOff className="w-3.5 h-3.5" /> Browser alerts on
                </>
              ) : (
                <>
                  <Bell className="w-3.5 h-3.5" /> Enable browser alerts
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {active.length === 0 ? (
        <p className="text-sm text-slate-500 py-6 text-center">
          No active alerts. Dismissed items stay hidden in this browser.
        </p>
      ) : (
        <div className="divide-y divide-slate-700/20">
          {active.map((a) => (
            <AlertRow key={a.id} alert={a} onDismiss={dismissAlert} />
          ))}
        </div>
      )}
      {!compact && active.length >= maxItems && (
        <p className="text-[10px] text-slate-600 mt-3 text-center">
          Showing top {maxItems} matches. See <Link href="/alerts" className="text-cyan-500">all alerts</Link>.
        </p>
      )}
    </div>
  );
}
