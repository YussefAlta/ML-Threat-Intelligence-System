"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Treemap,
  XAxis,
  YAxis,
} from "recharts";
import type { Stats } from "@/lib/types";
import { SOURCE_COLORS, CATEGORY_COLORS, RISK_COLORS } from "@/lib/types";

function DarkTip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number }>;
}) {
  if (!active || !payload?.length) return null;
  const p = payload[0];
  return (
    <div className="bg-slate-800 border border-slate-600 rounded-lg px-2 py-1.5 text-xs shadow-xl">
      <span className="text-slate-300">{p.name}</span>
      <span className="text-slate-100 font-mono ml-2">{p.value?.toLocaleString()}</span>
    </div>
  );
}

export function ThreatLandscape({ stats }: { stats: Stats }) {
  const sourceChildren = stats.sources.map((s) => ({
    name: s.name.replace(/_/g, " "),
    value: s.count,
    fill: SOURCE_COLORS[s.name] ?? "#64748b",
  }));

  const treemapLeaves = sourceChildren;

  const labelRows = stats.labels.map((l) => ({
    name: l.name,
    count: l.count,
    fill: CATEGORY_COLORS[l.name] ?? "#64748b",
  }));

  const riskRows = stats.risk_tiers.map((r) => ({
    name: r.name,
    count: r.count,
    fill: RISK_COLORS[r.name] ?? "#64748b",
  }));

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
      <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-4">
        <h3 className="text-sm font-semibold text-slate-200 mb-1">
          Abstract threat landscape
        </h3>
        <p className="text-xs text-slate-500 mb-4">
          Collection volume by OSINT source (tile area = document count)
        </p>
        {treemapLeaves.length > 0 ? (
          <div className="h-[340px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <Treemap
                data={treemapLeaves}
                dataKey="value"
                nameKey="name"
                stroke="#0f172a"
                fill="#475569"
                aspectRatio={4 / 3}
              >
                <Tooltip content={<DarkTip />} />
              </Treemap>
            </ResponsiveContainer>
          </div>
        ) : (
          <p className="text-slate-500 text-sm py-12 text-center">No source data</p>
        )}
      </div>

      <div className="space-y-6">
        <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-4">
          <h3 className="text-sm font-semibold text-slate-200 mb-3">
            Risk tier distribution
          </h3>
          <div className="h-[200px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskRows} layout="vertical" margin={{ left: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={72}
                  stroke="#64748b"
                  fontSize={11}
                  tickFormatter={(v) => String(v).slice(0, 12)}
                />
                <Tooltip content={<DarkTip />} cursor={{ fill: "#1e293b" }} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {riskRows.map((e) => (
                    <Cell key={e.name} fill={e.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-slate-800/50 rounded-xl border border-slate-700/40 p-4">
          <h3 className="text-sm font-semibold text-slate-200 mb-3">
            Threat categories (labeled docs)
          </h3>
          <div className="h-[200px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={labelRows} margin={{ bottom: 40 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis
                  dataKey="name"
                  stroke="#64748b"
                  fontSize={10}
                  angle={-25}
                  textAnchor="end"
                  height={60}
                />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip content={<DarkTip />} cursor={{ fill: "#1e293b" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {labelRows.map((e) => (
                    <Cell key={e.name} fill={e.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
