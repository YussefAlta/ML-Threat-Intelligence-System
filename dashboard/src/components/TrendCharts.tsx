"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Stats } from "@/lib/types";
import { RISK_COLORS } from "@/lib/types";

function Tip({
  active,
  label,
  payload,
}: {
  active?: boolean;
  label?: string;
  payload?: Array<{ name?: string; value?: number; color?: string }>;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-slate-800 border border-slate-600 rounded-lg px-2 py-1.5 text-xs shadow-xl max-w-xs">
      <p className="text-slate-400 mb-1">{label}</p>
      {payload.map((p) => (
        <p key={String(p.name)} className="text-slate-100 font-mono">
          <span style={{ color: p.color }}>{p.name}: </span>
          {p.value?.toLocaleString()}
        </p>
      ))}
    </div>
  );
}

export function TrendCharts({ stats }: { stats: Stats }) {
  const trends = stats.trends;
  if (
    !trends ||
    !trends.documents_by_day?.length ||
    !trends.by_risk_by_day?.length
  ) {
    return (
      <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-8 text-center">
        <p className="text-slate-400 text-sm">
          No time-series data yet. Run{" "}
          <code className="text-cyan-400/90">python scripts/prepare_dashboard_data.py</code>{" "}
          on NLP-enriched JSONL that includes{" "}
          <code className="text-cyan-400/90">collected_at</code> or{" "}
          <code className="text-cyan-400/90">published_at</code> (produced by the latest
          enricher).
        </p>
      </div>
    );
  }

  const docLine = trends.documents_by_day;
  const riskStack = trends.by_risk_by_day;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-4">
        <h3 className="text-sm font-semibold text-slate-200 mb-1">
          Document volume over time
        </h3>
        <p className="text-xs text-slate-500 mb-4">
          By collection/publication day (last {trends.window_days} days in dataset)
        </p>
        <div className="h-[280px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={docLine} margin={{ left: 0, right: 8 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis
                dataKey="day"
                stroke="#64748b"
                fontSize={10}
                tickFormatter={(d) => (d ? String(d).slice(5) : "")}
              />
              <YAxis stroke="#64748b" fontSize={11} width={40} />
              <Tooltip content={<Tip />} />
              <Line
                type="monotone"
                dataKey="count"
                name="Documents"
                stroke="#22d3ee"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-4">
        <h3 className="text-sm font-semibold text-slate-200 mb-1">
          Risk tier mix over time
        </h3>
        <p className="text-xs text-slate-500 mb-4">Stacked counts per day</p>
        <div className="h-[280px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={riskStack} margin={{ left: 0, right: 8 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis
                dataKey="day"
                stroke="#64748b"
                fontSize={10}
                tickFormatter={(d) => (d ? String(d).slice(5) : "")}
              />
              <YAxis stroke="#64748b" fontSize={11} width={40} />
              <Tooltip content={<Tip />} />
              {(["critical", "high", "medium", "low"] as const).map((k) => (
                <Area
                  key={k}
                  type="monotone"
                  dataKey={k}
                  name={k}
                  stackId="r"
                  stroke={RISK_COLORS[k]}
                  fill={RISK_COLORS[k]}
                  fillOpacity={0.55}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
