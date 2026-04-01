"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { Network, BarChart3, ShieldAlert, Loader2 } from "lucide-react";
import { PipelineAnimation } from "@/components/PipelineAnimation";
import { StatCards } from "@/components/StatCards";
import { RecentThreats } from "@/components/RecentThreats";
import { ThreatLandscape } from "@/components/ThreatLandscape";
import { TrendCharts } from "@/components/TrendCharts";
import { AlertFeed } from "@/components/AlertFeed";
import { useIntelligence } from "@/context/IntelligenceContext";

export default function OverviewPage() {
  const { stats, docs, loading, error } = useIntelligence();

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center h-[80vh]">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
        <span className="ml-3 text-slate-400">Loading command center…</span>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="max-w-xl mx-auto py-16 text-center text-slate-400">
        <p>Could not load intelligence data. Ensure dashboard/public/data/stats.json exists.</p>
      </div>
    );
  }

  const previewThreats = docs.slice(0, 8);

  return (
    <div className="space-y-10 max-w-[1600px]">
      <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
        <h1 className="text-2xl font-bold text-slate-100">Command center</h1>
        <p className="text-sm text-slate-500 mt-1 max-w-3xl">
          Centralized view of collected and analyzed threat intelligence: landscape,
          trends, correlation graph, and prioritized alerts for analysts.
        </p>
        <div className="flex flex-wrap gap-2 mt-4">
          <Link
            href="/graph"
            className="inline-flex items-center gap-2 text-xs font-medium px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/25 hover:bg-cyan-500/15"
          >
            <Network className="w-3.5 h-3.5" />
            Entity graph
          </Link>
          <Link
            href="/alerts"
            className="inline-flex items-center gap-2 text-xs font-medium px-3 py-1.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/25 hover:bg-amber-500/15"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            All alerts
          </Link>
          <Link
            href="/analytics"
            className="inline-flex items-center gap-2 text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 border border-slate-600 hover:bg-slate-700"
          >
            <BarChart3 className="w-3.5 h-3.5" />
            Deep analytics
          </Link>
        </div>
      </motion.div>

      <PipelineAnimation stats={stats} />
      <StatCards stats={stats} />

      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-slate-200">Alerts</h2>
        <AlertFeed compact maxItems={8} />
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-slate-200">
          Threat landscape
        </h2>
        <ThreatLandscape stats={stats} />
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-slate-200">Trends</h2>
        <TrendCharts stats={stats} />
      </section>

      <section className="space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <h2 className="text-lg font-semibold text-slate-200">
            Entity relationship graph
          </h2>
          <Link
            href="/graph"
            className="text-sm text-cyan-400 hover:text-cyan-300"
          >
            Open full graph →
          </Link>
        </div>
        <div className="bg-slate-800/40 rounded-xl border border-slate-700/35 p-6 text-center">
          <p className="text-slate-400 text-sm mb-4">
            Explore extracted relations and entity co-occurrence in the interactive graph.
            Data is sampled for performance (~200 nodes max).
          </p>
          <Link
            href="/graph"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 text-sm font-medium hover:bg-cyan-600/30"
          >
            <Network className="w-4 h-4" />
            Open graph
          </Link>
        </div>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-slate-200 mb-4">
          Recent threats
        </h2>
        <RecentThreats threats={previewThreats} />
      </section>
    </div>
  );
}
