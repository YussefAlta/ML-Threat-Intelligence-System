import type { EnrichedDocument } from "@/lib/types";

export type AlertSeverity = "critical" | "high" | "medium";

export interface AlertRule {
  id: string;
  name: string;
  severity: AlertSeverity;
  predicate: (doc: EnrichedDocument) => boolean;
  message: (doc: EnrichedDocument) => string;
}

const labelConf = (doc: EnrichedDocument, label: string) =>
  doc.predicted_labels?.[label] ?? 0;

export const ALERT_RULES: AlertRule[] = [
  {
    id: "risk_critical",
    name: "Critical risk tier",
    severity: "critical",
    predicate: (d) => d.risk_assessment?.risk_tier === "critical",
    message: (d) =>
      `Document scored as critical risk: ${(d.title || d.id).slice(0, 120)}`,
  },
  {
    id: "ransomware_high_confidence",
    name: "Ransomware (high confidence)",
    severity: "high",
    predicate: (d) => labelConf(d, "ransomware") >= 0.5,
    message: (d) =>
      `Ransomware label confidence ${(labelConf(d, "ransomware") * 100).toFixed(0)}% — ${(d.title || d.id).slice(0, 100)}`,
  },
  {
    id: "cisa_kev_high_cvss",
    name: "CISA KEV with elevated CVSS",
    severity: "high",
    predicate: (d) =>
      d.source === "cisa_kev" &&
      (d.metadata?.cvss?.score ?? 0) >= 7,
    message: (d) =>
      `CISA KEV entry CVSS ${d.metadata?.cvss?.score} — ${(d.title || d.id).slice(0, 100)}`,
  },
  {
    id: "exploit_and_critical",
    name: "Exploit content at critical risk",
    severity: "critical",
    predicate: (d) =>
      labelConf(d, "exploit") >= 0.4 &&
      d.risk_assessment?.risk_tier === "critical",
    message: (d) =>
      `Exploit-labeled document in critical tier: ${(d.title || d.id).slice(0, 100)}`,
  },
  {
    id: "high_risk_score",
    name: "Very high risk score",
    severity: "high",
    predicate: (d) => {
      const s = d.risk_assessment?.risk_score ?? 0;
      const t = d.risk_assessment?.risk_tier;
      return s >= 0.85 && t !== "critical";
    },
    message: (d) =>
      `Risk score ${((d.risk_assessment?.risk_score ?? 0) * 100).toFixed(0)}% — ${(d.title || d.id).slice(0, 100)}`,
  },
];
