"use client";

import { useEffect, useRef, useState } from "react";
import { motion, useInView } from "framer-motion";
import type { Stats } from "@/lib/types";
import { SOURCE_COLORS } from "@/lib/types";

interface PipelineAnimationProps {
  stats: Stats | null;
}

/* ------------------------------------------------------------------ */
/*  Source definitions                                                  */
/* ------------------------------------------------------------------ */

const sources = [
  { key: "exploitdb", label: "ExploitDB", color: SOURCE_COLORS.exploitdb },
  { key: "ransomwatch", label: "ransomwatch", color: SOURCE_COLORS.ransomwatch },
  { key: "cisa_kev", label: "CISA KEV", color: SOURCE_COLORS.cisa_kev },
  { key: "mitre_attack", label: "MITRE ATT&CK", color: SOURCE_COLORS.mitre_attack },
  { key: "phishtank", label: "PhishTank", color: SOURCE_COLORS.phishtank },
  { key: "threatfox", label: "ThreatFox", color: SOURCE_COLORS.threatfox },
  { key: "nvd_ref", label: "NIST NVD", color: SOURCE_COLORS.nvd_ref },
];

const stagesDef = [
  { label: "INGESTION", sub: "10,000 docs", x: 360 },
  { label: "NLP ENRICHMENT", sub: "Classify  /  Extract  /  Score", x: 620 },
  { label: "S3 STORAGE", sub: "Enriched corpus", x: 880 },
];

/* Layout constants */
const SOURCE_START_Y = 40;
const SOURCE_SPACING = 48;
const SOURCE_X = 30;
const SOURCE_BOX_W = 110;
const STAGE_Y = 175;
const STAGE_BOX_H = 70;
const STAGE_BOX_W = 140;

/* ------------------------------------------------------------------ */
/*  Count-up number                                                    */
/* ------------------------------------------------------------------ */

function CountUp({
  target,
  duration = 1.8,
  decimals = 0,
}: {
  target: number;
  duration?: number;
  decimals?: number;
}) {
  const [value, setValue] = useState(0);
  const ref = useRef<HTMLSpanElement>(null);
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

  return (
    <span ref={ref}>
      {decimals > 0
        ? value.toFixed(decimals)
        : Math.round(value).toLocaleString()}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  SVG flowing dot using <animateMotion>                              */
/* ------------------------------------------------------------------ */

function FlowDot({
  color,
  delay,
  duration,
  id,
}: {
  color: string;
  delay: number;
  duration: number;
  id: string;
}) {
  return (
    <circle r={3} fill={color} opacity={0} filter="url(#dotGlow)">
      <animate
        attributeName="opacity"
        values="0;0;1;1;1;0"
        keyTimes="0;0.01;0.05;0.9;0.95;1"
        dur={`${duration}s`}
        begin={`${delay}s`}
        repeatCount="indefinite"
      />
      <animateMotion
        dur={`${duration}s`}
        begin={`${delay}s`}
        repeatCount="indefinite"
        fill="freeze"
      >
        <mpath href={`#${id}`} />
      </animateMotion>
    </circle>
  );
}

/* ------------------------------------------------------------------ */
/*  Path helpers                                                       */
/* ------------------------------------------------------------------ */

function getSourceToIngestionPath(index: number): string {
  const sy = SOURCE_START_Y + index * SOURCE_SPACING;
  const sx = SOURCE_X + SOURCE_BOX_W;
  const tx = stagesDef[0].x;
  const ty = STAGE_Y;
  const midX = sx + (tx - sx) * 0.5;
  return `M ${sx} ${sy} C ${midX} ${sy}, ${midX} ${ty}, ${tx} ${ty}`;
}

function getStagePath(fromIdx: number, toIdx: number): string {
  const sx = stagesDef[fromIdx].x + STAGE_BOX_W;
  const tx = stagesDef[toIdx].x;
  const midX = sx + (tx - sx) * 0.5;
  return `M ${sx} ${STAGE_Y} C ${midX} ${STAGE_Y}, ${midX} ${STAGE_Y}, ${tx} ${STAGE_Y}`;
}

/* ------------------------------------------------------------------ */
/*  Main component                                                     */
/* ------------------------------------------------------------------ */

export function PipelineAnimation({ stats }: PipelineAnimationProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const inView = useInView(containerRef, { once: true, amount: 0.3 });

  const stagePath01 = getStagePath(0, 1);
  const stagePath12 = getStagePath(1, 2);

  return (
    <div ref={containerRef} className="relative w-full">
      <div className="bg-slate-900/60 rounded-2xl border border-slate-800/50 p-6 overflow-hidden glow-blue">
        <svg
          viewBox="0 0 1050 380"
          className="w-full h-auto"
          style={{ maxHeight: "420px" }}
        >
          <defs>
            {/* Glow filter for dots */}
            <filter id="dotGlow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Glow filter for wires */}
            <filter id="wireGlow" x="-10%" y="-10%" width="120%" height="120%">
              <feGaussianBlur stdDeviation="2" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Stage box gradient */}
            <linearGradient id="stageGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#1e293b" />
              <stop offset="100%" stopColor="#0f172a" />
            </linearGradient>

            {/* Stage border gradient */}
            <linearGradient id="stageBorder" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.2" />
            </linearGradient>

            {/* Define reusable path elements for animateMotion mpath */}
            {sources.map((src, i) => (
              <path
                key={`pathdef-src-${src.key}`}
                id={`path-src-${src.key}`}
                d={getSourceToIngestionPath(i)}
                fill="none"
              />
            ))}
            <path id="path-stage-01" d={stagePath01} fill="none" />
            <path id="path-stage-12" d={stagePath12} fill="none" />
          </defs>

          {/* ======================================================= */}
          {/*  Wire paths: sources to Ingestion                        */}
          {/* ======================================================= */}
          {sources.map((src, i) => {
            const d = getSourceToIngestionPath(i);
            return (
              <g key={`wire-${src.key}`}>
                <motion.path
                  d={d}
                  fill="none"
                  stroke={src.color}
                  strokeWidth={1}
                  strokeOpacity={0.15}
                  filter="url(#wireGlow)"
                  initial={{ pathLength: 0 }}
                  animate={inView ? { pathLength: 1 } : {}}
                  transition={{
                    duration: 1.2,
                    delay: 0.1 * i,
                    ease: "easeOut",
                  }}
                />
                {/* Flowing dots along source paths */}
                {inView &&
                  [0, 1, 2].map((dotIdx) => (
                    <FlowDot
                      key={`dot-${src.key}-${dotIdx}`}
                      id={`path-src-${src.key}`}
                      color={src.color}
                      delay={1.5 + i * 0.2 + dotIdx * 2.8}
                      duration={3.5}
                    />
                  ))}
              </g>
            );
          })}

          {/* ======================================================= */}
          {/*  Wire paths: stage to stage                               */}
          {/* ======================================================= */}
          {[
            { d: stagePath01, id: "path-stage-01" },
            { d: stagePath12, id: "path-stage-12" },
          ].map(({ d, id }, i) => (
            <g key={`stage-wire-${i}`}>
              <motion.path
                d={d}
                fill="none"
                stroke="#06b6d4"
                strokeWidth={1.5}
                strokeOpacity={0.2}
                filter="url(#wireGlow)"
                initial={{ pathLength: 0 }}
                animate={inView ? { pathLength: 1 } : {}}
                transition={{
                  duration: 1,
                  delay: 1.0 + i * 0.4,
                  ease: "easeOut",
                }}
              />
              {inView &&
                [0, 1, 2, 3].map((dotIdx) => (
                  <FlowDot
                    key={`sdot-${i}-${dotIdx}`}
                    id={id}
                    color="#06b6d4"
                    delay={2.0 + i * 0.6 + dotIdx * 1.8}
                    duration={2.5}
                  />
                ))}
            </g>
          ))}

          {/* ======================================================= */}
          {/*  Source nodes                                              */}
          {/* ======================================================= */}
          {sources.map((src, i) => {
            const y = SOURCE_START_Y + i * SOURCE_SPACING;
            return (
              <motion.g
                key={src.key}
                initial={{ opacity: 0, x: -20 }}
                animate={inView ? { opacity: 1, x: 0 } : {}}
                transition={{ duration: 0.5, delay: 0.08 * i }}
              >
                <rect
                  x={SOURCE_X}
                  y={y - 14}
                  width={SOURCE_BOX_W}
                  height={28}
                  rx={6}
                  fill="#0f172a"
                  stroke={src.color}
                  strokeWidth={1}
                  strokeOpacity={0.4}
                />
                <text
                  x={SOURCE_X + SOURCE_BOX_W / 2}
                  y={y + 1}
                  textAnchor="middle"
                  dominantBaseline="middle"
                  fill={src.color}
                  fontSize={10}
                  fontWeight={600}
                  fontFamily="var(--font-geist-sans), system-ui, sans-serif"
                >
                  {src.label}
                </text>
              </motion.g>
            );
          })}

          {/* ======================================================= */}
          {/*  Stage boxes                                              */}
          {/* ======================================================= */}
          {stagesDef.map((stage, i) => (
            <motion.g
              key={stage.label}
              initial={{ opacity: 0, y: 20 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.6, delay: 0.8 + i * 0.25 }}
            >
              <rect
                x={stage.x}
                y={STAGE_Y - STAGE_BOX_H / 2}
                width={STAGE_BOX_W}
                height={STAGE_BOX_H}
                rx={10}
                fill="url(#stageGrad)"
                stroke="url(#stageBorder)"
                strokeWidth={1.5}
              />
              {/* Subtle inner glow */}
              <rect
                x={stage.x + 1}
                y={STAGE_Y - STAGE_BOX_H / 2 + 1}
                width={STAGE_BOX_W - 2}
                height={STAGE_BOX_H - 2}
                rx={9}
                fill="none"
                stroke="#06b6d4"
                strokeWidth={0.5}
                strokeOpacity={0.1}
              />
              <text
                x={stage.x + STAGE_BOX_W / 2}
                y={STAGE_Y - 6}
                textAnchor="middle"
                dominantBaseline="middle"
                fill="#e2e8f0"
                fontSize={11}
                fontWeight={700}
                letterSpacing="0.05em"
                fontFamily="var(--font-geist-sans), system-ui, sans-serif"
              >
                {stage.label}
              </text>
              <text
                x={stage.x + STAGE_BOX_W / 2}
                y={STAGE_Y + 14}
                textAnchor="middle"
                dominantBaseline="middle"
                fill="#64748b"
                fontSize={9}
                fontFamily="var(--font-geist-sans), system-ui, sans-serif"
              >
                {stage.sub}
              </text>
            </motion.g>
          ))}

          {/* ======================================================= */}
          {/*  Count labels below stages                                */}
          {/* ======================================================= */}
          {inView && stats && (
            <>
              <foreignObject
                x={stagesDef[0].x}
                y={STAGE_Y + STAGE_BOX_H / 2 + 12}
                width={STAGE_BOX_W}
                height={30}
              >
                <div className="flex justify-center">
                  <span className="text-xs font-mono text-cyan-400/80">
                    <CountUp target={stats.total_documents} duration={2} /> docs
                  </span>
                </div>
              </foreignObject>
              <foreignObject
                x={stagesDef[1].x}
                y={STAGE_Y + STAGE_BOX_H / 2 + 12}
                width={STAGE_BOX_W}
                height={30}
              >
                <div className="flex justify-center">
                  <span className="text-xs font-mono text-cyan-400/80">
                    <CountUp target={stats.total_entities} duration={2} />{" "}
                    entities
                  </span>
                </div>
              </foreignObject>
              <foreignObject
                x={stagesDef[2].x}
                y={STAGE_Y + STAGE_BOX_H / 2 + 12}
                width={STAGE_BOX_W}
                height={30}
              >
                <div className="flex justify-center">
                  <span className="text-xs font-mono text-emerald-400/80">
                    <CountUp target={stats.docs_labeled} duration={2} /> labeled
                  </span>
                </div>
              </foreignObject>
            </>
          )}

          {/* ======================================================= */}
          {/*  Pipeline title                                           */}
          {/* ======================================================= */}
          <motion.text
            x={525}
            y={340}
            textAnchor="middle"
            fill="#475569"
            fontSize={11}
            fontFamily="var(--font-geist-mono), monospace"
            letterSpacing="0.1em"
            initial={{ opacity: 0 }}
            animate={inView ? { opacity: 1 } : {}}
            transition={{ duration: 1, delay: 2 }}
          >
            ML THREAT INTELLIGENCE PIPELINE
          </motion.text>

          {/* Decorative slow scan line */}
          {inView && (
            <motion.line
              x1={0}
              x2={1050}
              y1={0}
              y2={0}
              stroke="#06b6d4"
              strokeWidth={1}
              strokeOpacity={0.06}
              animate={{ y1: [0, 380, 0], y2: [0, 380, 0] }}
              transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
            />
          )}
        </svg>
      </div>
    </div>
  );
}
