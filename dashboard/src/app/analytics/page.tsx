'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Loader2, BarChart3 } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { Stats, CATEGORY_COLORS, SOURCE_COLORS, RISK_COLORS } from '@/lib/types';

const ENTITY_COLORS = [
  '#06b6d4', '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b',
  '#10b981', '#ef4444', '#6366f1', '#f97316',
];

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ name: string; value: number; payload: Record<string, string | number> }>;
  label?: string;
}

function DarkTooltip({ active, payload, label }: CustomTooltipProps) {
  if (!active || !payload?.length) return null;
  const displayLabel = label || String(payload[0]?.payload?.name ?? '');
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 shadow-xl">
      <p className="text-slate-300 text-xs font-medium mb-1">{displayLabel}</p>
      {payload.map((entry, i) => (
        <p key={i} className="text-slate-100 text-sm font-mono">
          {entry.value.toLocaleString()}
        </p>
      ))}
    </div>
  );
}

function ChartCard({ title, delay, children }: { title: string; delay: number; children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="bg-slate-800 rounded-xl border border-slate-700 p-5"
    >
      <h3 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">{title}</h3>
      {children}
    </motion.div>
  );
}

export default function AnalyticsPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/data/stats.json')
      .then((r) => r.json())
      .then((data: Stats) => {
        setStats(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  if (loading || !stats) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
        <span className="ml-3 text-slate-300 text-lg">Loading analytics...</span>
      </div>
    );
  }

  const labelData = stats.labels.map((l) => ({
    name: l.name,
    count: l.count,
    fill: CATEGORY_COLORS[l.name] || '#64748b',
  }));

  const sourceData = stats.sources.map((s) => ({
    name: s.name,
    count: s.count,
    fill: SOURCE_COLORS[s.name] || '#64748b',
  }));

  const riskData = stats.risk_tiers.map((r) => ({
    name: r.name,
    count: r.count,
    fill: RISK_COLORS[r.name] || '#64748b',
  }));

  const entityData = stats.entity_types.map((e, i) => ({
    name: e.name,
    count: e.count,
    fill: ENTITY_COLORS[i % ENTITY_COLORS.length],
  }));

  const topCves = stats.top_cves.slice(0, 10).map((c) => ({
    name: c.value,
    count: c.count,
  }));

  const topMalware = stats.top_malware.slice(0, 10).map((m) => ({
    name: m.value,
    count: m.count,
  }));

  const renderPieLegend = (data: Array<{ name: string; count: number; fill: string }>) => (
    <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 justify-center">
      {data.map((item) => (
        <div key={item.name} className="flex items-center gap-1.5 text-xs text-slate-400">
          <div className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: item.fill }} />
          <span>{item.name}</span>
          <span className="font-mono text-slate-500">({item.count.toLocaleString()})</span>
        </div>
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="max-w-[1600px] mx-auto px-6 py-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-3xl font-bold text-slate-100 flex items-center gap-3">
            <BarChart3 className="w-8 h-8 text-cyan-400" />
            Analytics
          </h1>
          <p className="text-slate-400 mt-1">
            Corpus statistics across {stats.total_documents.toLocaleString()} documents
          </p>
        </motion.div>

        {/* Charts Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Label Distribution */}
          <ChartCard title="Label Distribution" delay={0.05}>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={labelData} layout="vertical" margin={{ left: 20, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={{ stroke: '#475569' }} />
                <YAxis
                  type="category"
                  dataKey="name"
                  tick={{ fill: '#94a3b8', fontSize: 12 }}
                  axisLine={{ stroke: '#475569' }}
                  width={90}
                />
                <Tooltip content={<DarkTooltip />} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {labelData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>

          {/* Source Breakdown */}
          <ChartCard title="Source Breakdown" delay={0.1}>
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie
                  data={sourceData}
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  innerRadius={45}
                  dataKey="count"
                  stroke="#0f172a"
                  strokeWidth={2}
                >
                  {sourceData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip content={<DarkTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            {renderPieLegend(sourceData)}
          </ChartCard>

          {/* Risk Distribution */}
          <ChartCard title="Risk Distribution" delay={0.15}>
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie
                  data={riskData}
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  innerRadius={45}
                  dataKey="count"
                  stroke="#0f172a"
                  strokeWidth={2}
                >
                  {riskData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip content={<DarkTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            {renderPieLegend(riskData)}
          </ChartCard>

          {/* Entity Types */}
          <ChartCard title="Entity Types" delay={0.2}>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={entityData} margin={{ left: 10, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                <XAxis
                  dataKey="name"
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                  axisLine={{ stroke: '#475569' }}
                  angle={-30}
                  textAnchor="end"
                  height={60}
                />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={{ stroke: '#475569' }} />
                <Tooltip content={<DarkTooltip />} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {entityData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>

          {/* Top 10 CVEs */}
          <ChartCard title="Top 10 CVEs" delay={0.25}>
            {topCves.length === 0 ? (
              <div className="h-[280px] flex items-center justify-center text-slate-500">No CVE data available</div>
            ) : (
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={topCves} layout="vertical" margin={{ left: 30, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={{ stroke: '#475569' }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    tick={{ fill: '#94a3b8', fontSize: 10 }}
                    axisLine={{ stroke: '#475569' }}
                    width={130}
                  />
                  <Tooltip content={<DarkTooltip />} />
                  <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </ChartCard>

          {/* Top 10 Malware */}
          <ChartCard title="Top 10 Malware" delay={0.3}>
            {topMalware.length === 0 ? (
              <div className="h-[280px] flex items-center justify-center text-slate-500">No malware data available</div>
            ) : (
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={topMalware} layout="vertical" margin={{ left: 30, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={{ stroke: '#475569' }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    tick={{ fill: '#94a3b8', fontSize: 10 }}
                    axisLine={{ stroke: '#475569' }}
                    width={130}
                  />
                  <Tooltip content={<DarkTooltip />} />
                  <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </ChartCard>
        </div>
      </div>
    </div>
  );
}
