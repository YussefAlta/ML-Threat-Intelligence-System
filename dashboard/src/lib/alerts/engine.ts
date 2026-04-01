import type { EnrichedDocument } from "@/lib/types";
import { ALERT_RULES, type AlertRule, type AlertSeverity } from "./rules";

export interface IntelligenceAlert {
  id: string;
  ruleId: string;
  docId: string;
  severity: AlertSeverity;
  title: string;
  summary: string;
  createdAt: string;
}

const SEVERITY_RANK: Record<AlertSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
};

export function evaluateAlerts(
  docs: EnrichedDocument[],
  rules: AlertRule[] = ALERT_RULES,
): IntelligenceAlert[] {
  const out: IntelligenceAlert[] = [];
  for (const doc of docs) {
    for (const rule of rules) {
      try {
        if (rule.predicate(doc)) {
          out.push({
            id: `${rule.id}::${doc.id}`,
            ruleId: rule.id,
            docId: doc.id,
            severity: rule.severity,
            title: rule.name,
            summary: rule.message(doc),
            createdAt:
              doc.collected_at ||
              doc.published_at ||
              doc.enriched_at ||
              "",
          });
        }
      } catch {
        /* skip rule failures for malformed docs */
      }
    }
  }
  out.sort((a, b) => {
    const s = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (s !== 0) return s;
    return (b.createdAt || "").localeCompare(a.createdAt || "");
  });
  return out;
}
