"use client";

import { motion } from "framer-motion";
import type { EnrichedDocument } from "@/lib/types";
import { SOURCE_COLORS, CATEGORY_COLORS, RISK_COLORS } from "@/lib/types";
import { Fingerprint } from "lucide-react";

/* ------------------------------------------------------------------ */
/*  Source badge                                                       */
/* ------------------------------------------------------------------ */

function SourceBadge({ source }: { source: string }) {
  const color = SOURCE_COLORS[source] ?? "#64748b";
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider"
      style={{
        color,
        backgroundColor: `${color}15`,
        border: `1px solid ${color}30`,
      }}
    >
      {source.replace(/_/g, " ")}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Risk tier badge                                                    */
/* ------------------------------------------------------------------ */

function RiskBadge({ tier }: { tier: string }) {
  const color = RISK_COLORS[tier] ?? "#64748b";
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
      style={{
        color,
        backgroundColor: `${color}15`,
        border: `1px solid ${color}30`,
      }}
    >
      {tier}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Label badge                                                        */
/* ------------------------------------------------------------------ */

function LabelBadge({ label }: { label: string }) {
  const color = CATEGORY_COLORS[label] ?? "#64748b";
  return (
    <span
      className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-medium"
      style={{
        color: `${color}cc`,
        backgroundColor: `${color}10`,
      }}
    >
      {label}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Threat card                                                        */
/* ------------------------------------------------------------------ */

function ThreatCard({
  doc,
  index,
}: {
  doc: EnrichedDocument;
  index: number;
}) {
  const labels = Object.keys(doc.predicted_labels);
  const entityCount = doc.entity_summary?.total ?? doc.entities?.length ?? 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: 0.05 * index }}
      className="bg-slate-800/40 rounded-xl border border-slate-700/25 p-4 hover:border-slate-600/40 hover:bg-slate-800/60 transition-all duration-300 group cursor-default"
    >
      {/* Title */}
      <h3 className="text-sm font-medium text-slate-200 line-clamp-2 leading-snug mb-3 group-hover:text-slate-100 transition-colors">
        {doc.title}
      </h3>

      {/* Badges row */}
      <div className="flex flex-wrap items-center gap-1.5 mb-3">
        <SourceBadge source={doc.source} />
        {doc.risk_assessment && <RiskBadge tier={doc.risk_assessment.risk_tier} />}
      </div>

      {/* Label badges */}
      {labels.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {labels.map((l) => (
            <LabelBadge key={l} label={l} />
          ))}
        </div>
      )}

      {/* Footer */}
      <div className="flex items-center justify-between pt-2 border-t border-slate-700/20">
        <div className="flex items-center gap-1.5 text-slate-500">
          <Fingerprint className="w-3 h-3" />
          <span className="text-[10px] font-medium">
            {entityCount} {entityCount === 1 ? "entity" : "entities"}
          </span>
        </div>
        {doc.risk_assessment && (
          <span className="text-[10px] font-mono text-slate-600">
            risk: {doc.risk_assessment.risk_score.toFixed(2)}
          </span>
        )}
      </div>
    </motion.div>
  );
}

/* ------------------------------------------------------------------ */
/*  Recent threats grid                                                */
/* ------------------------------------------------------------------ */

export function RecentThreats({
  threats,
}: {
  threats: EnrichedDocument[];
}) {
  if (threats.length === 0) {
    return (
      <div className="text-sm text-slate-500 py-8 text-center">
        No threats loaded.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {threats.map((doc, i) => (
        <ThreatCard key={doc.id} doc={doc} index={i} />
      ))}
    </div>
  );
}
