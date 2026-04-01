/** Shared types and palette maps for the threat intelligence dashboard. */

export type RiskTier = "critical" | "high" | "medium" | "low";

export interface NamedCount {
  name: string;
  count: number;
}

export interface LabelStat extends NamedCount {
  avg_confidence: number;
}

export interface TopValueCount {
  value: string;
  count: number;
}

export interface EvalMetric {
  name: string;
  precision: number;
  recall: number;
  f1: number;
  support: number;
}

export interface EvaluationBlock {
  classification_macro_f1: number;
  ner_macro_f1: number;
  classification_per_category: EvalMetric[];
  ner_per_type: EvalMetric[];
}

/** Daily aggregates for trend charts (from prepare_dashboard_data). */
export interface TrendsBlock {
  documents_by_day: Array<{ day: string; count: number }>;
  /** Each row: day + counts per top source columns */
  by_source_by_day: Array<Record<string, string | number>>;
  /** Each row: day + critical | high | medium | low */
  by_risk_by_day: Array<Record<string, string | number>>;
  window_days: number;
}

export interface Stats {
  total_documents: number;
  docs_labeled: number;
  docs_unlabeled: number;
  multi_label_docs: number;
  total_entities: number;
  total_relations: number;
  avg_entities_per_doc: number;
  sources: NamedCount[];
  labels: LabelStat[];
  risk_tiers: NamedCount[];
  entity_types: NamedCount[];
  relation_types: NamedCount[];
  top_cves: TopValueCount[];
  top_ips: TopValueCount[];
  top_domains: TopValueCount[];
  top_malware: TopValueCount[];
  top_organizations: TopValueCount[];
  evaluation: EvaluationBlock;
  trends?: TrendsBlock;
}

export interface ExtractedEntity {
  type: string;
  value: string;
  canonical_value?: string;
  method: string;
}

export interface RelationEdge {
  source: string;
  type: string;
  target: string;
  confidence: number;
  evidence: string;
}

export interface EntitySummary {
  total: number;
  unique_cves: string[];
  unique_ips: string[];
  unique_domains: string[];
  unique_hashes: {
    md5: string[];
    sha1: string[];
    sha256: string[];
  };
}

/** Optional trimmed CVE metadata copied from corpus at enrichment time. */
export interface EnrichedMetadata {
  cve_id?: string;
  cvss?: {
    score?: number;
    severity?: string;
    vector?: string;
    exploitability_score?: number;
    impact_score?: number;
  };
  cwe_ids?: string[];
}

export interface EnrichedDocument {
  id: string;
  title: string;
  source: string;
  predicted_labels: Record<string, number>;
  risk_assessment: {
    risk_tier: RiskTier;
    risk_score: number;
    contributing_factors: string[];
  };
  entity_summary: EntitySummary;
  entities: ExtractedEntity[];
  relations: RelationEdge[];
  enriched_at: string;
  enrichment_version: string;
  methods: {
    entity_extraction: string[];
  };
  published_at?: string;
  collected_at?: string;
  url?: string;
  metadata?: EnrichedMetadata;
}

/** Precomputed subgraph for the graph view (optional). */
export interface GraphSampleNode {
  id: string;
  label: string;
  type: string;
}

export interface GraphSampleEdge {
  source: string;
  target: string;
  relation_type: string;
  doc_id?: string;
}

export interface GraphSample {
  nodes: GraphSampleNode[];
  edges: GraphSampleEdge[];
  truncated: boolean;
  doc_sample_size: number;
}

export const SOURCE_COLORS: Record<string, string> = {
  exploitdb: "#f59e0b",
  ransomwatch: "#ef4444",
  cisa_kev: "#3b82f6",
  nvd_ref: "#0ea5e9",
  mitre_attack: "#a855f7",
  phishtank: "#14b8a6",
  threatfox: "#22c55e",
};

export const CATEGORY_COLORS: Record<string, string> = {
  vulnerability: "#f97316",
  exploit: "#eab308",
  phishing: "#06b6d4",
  ransomware: "#dc2626",
  threat_actor: "#8b5cf6",
  ioc: "#10b981",
};

export const RISK_COLORS: Record<string, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#facc15",
  low: "#4ade80",
};
