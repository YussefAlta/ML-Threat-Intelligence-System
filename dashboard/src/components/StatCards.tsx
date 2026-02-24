"use client";

import { useEffect, useRef, useState } from "react";
import { useInView } from "framer-motion";
import {
  FileText,
  Tags,
  Fingerprint,
  TrendingUp,
  AlertTriangle,
} from "lucide-react";
import type { Stats } from "@/lib/types";

/* ------------------------------------------------------------------ */
/*  Count-up hook                                                      */
/* ------------------------------------------------------------------ */

function useCountUp(target: number, duration = 1.5, decimals = 0) {
  const [value, setValue] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true });

  useEffect(() => {
    if (!inView) return;
    const start = performance.now();
    const step = (now: number) => {
      const elapsed = (now - start) / 1000;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(eased * target);
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [inView, target, duration]);

  const display =
    decimals > 0
      ? value.toFixed(decimals)
      : Math.round(value).toLocaleString();

  return { ref, display };
}

/* ------------------------------------------------------------------ */
/*  Stat card                                                          */
/* ------------------------------------------------------------------ */

interface StatCardProps {
  label: string;
  value: number;
  icon: React.ReactNode;
  decimals?: number;
  suffix?: string;
  color?: string;
}

function StatCard({
  label,
  value,
  icon,
  decimals = 0,
  suffix = "",
  color = "text-cyan-400",
}: StatCardProps) {
  const { ref, display } = useCountUp(value, 1.8, decimals);

  return (
    <div
      ref={ref}
      className="bg-slate-800/50 rounded-xl border border-slate-700/30 p-5 hover:border-slate-600/40 transition-all duration-300 group"
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider font-medium">
            {label}
          </p>
          <p className={`text-2xl font-bold mt-2 ${color} font-[family-name:var(--font-geist-mono)]`}>
            {display}
            {suffix && (
              <span className="text-base ml-0.5 font-normal text-slate-500">
                {suffix}
              </span>
            )}
          </p>
        </div>
        <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-700/20 text-slate-500 group-hover:text-slate-400 transition-colors">
          {icon}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  StatCards row                                                       */
/* ------------------------------------------------------------------ */

export function StatCards({ stats }: { stats: Stats }) {
  const criticalCount =
    stats.risk_tiers.find((t) => t.name === "critical")?.count ?? 0;
  const categoryCount = stats.labels.length;

  return (
    <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
      <StatCard
        label="Total Documents"
        value={stats.total_documents}
        icon={<FileText className="w-5 h-5" />}
      />
      <StatCard
        label="Threat Categories"
        value={categoryCount}
        icon={<Tags className="w-5 h-5" />}
        color="text-blue-400"
      />
      <StatCard
        label="Entities Extracted"
        value={stats.total_entities}
        icon={<Fingerprint className="w-5 h-5" />}
        color="text-violet-400"
      />
      <StatCard
        label="Macro F1"
        value={stats.evaluation.classification_macro_f1}
        decimals={2}
        icon={<TrendingUp className="w-5 h-5" />}
        color="text-emerald-400"
      />
      <StatCard
        label="Critical Risks"
        value={criticalCount}
        icon={<AlertTriangle className="w-5 h-5" />}
        color="text-red-400"
      />
    </div>
  );
}
