"use client";

import { useEffect, useState } from "react";
import { PipelineAnimation } from "@/components/PipelineAnimation";
import { StatCards } from "@/components/StatCards";
import { RecentThreats } from "@/components/RecentThreats";
import type { Stats, EnrichedDocument } from "@/lib/types";

export default function Home() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [threats, setThreats] = useState<EnrichedDocument[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch("/data/stats.json").then((r) => r.json()),
      fetch("/data/enriched.json").then((r) => r.json()),
    ])
      .then(([statsData, enrichedData]) => {
        setStats(statsData);
        setThreats(enrichedData.slice(0, 8));
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load data:", err);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[80vh]">
        <div className="flex flex-col items-center gap-4">
          <div className="w-8 h-8 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
          <p className="text-sm text-slate-500">Loading intelligence data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 max-w-[1400px]">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">
          Threat Intelligence Overview
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Real-time ML pipeline monitoring and threat analysis
        </p>
      </div>

      {/* Pipeline Hero */}
      <PipelineAnimation stats={stats} />

      {/* Stat Cards */}
      {stats && <StatCards stats={stats} />}

      {/* Recent Threats */}
      <div>
        <h2 className="text-lg font-semibold text-slate-200 mb-4">
          Recent Threats
        </h2>
        <RecentThreats threats={threats} />
      </div>
    </div>
  );
}
