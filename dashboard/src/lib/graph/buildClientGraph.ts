import type { EnrichedDocument, GraphSample } from "@/lib/types";

const CO_OCC_TYPES = new Set([
  "cve_id",
  "domain",
  "malware",
  "organization",
  "ipv4",
  "ipv6",
]);
const GRAPH_DOC_CAP = 150;
const GRAPH_MAX_NODES = 200;
const GRAPH_MAX_EDGES = 400;

function nodeId(raw: string, etype: string): string {
  return `${etype}:${raw}`.slice(0, 240);
}

/**
 * Client-side graph sample when graph_sample.json is missing or empty.
 * Mirrors scripts/prepare_dashboard_data.build_graph_sample.
 */
export function buildClientGraph(docs: EnrichedDocument[]): GraphSample {
  const scored = [...docs].sort(
    (a, b) =>
      (b.risk_assessment?.risk_score ?? 0) -
      (a.risk_assessment?.risk_score ?? 0),
  );
  const sampleDocs = scored.slice(0, GRAPH_DOC_CAP);

  const nodes: Record<string, { id: string; label: string; type: string }> = {};
  const edges: GraphSample["edges"] = [];
  const edgeSeen = new Set<string>();

  function addNode(nid: string, label: string, ntype: string) {
    if (nodes[nid] || Object.keys(nodes).length >= GRAPH_MAX_NODES) return;
    nodes[nid] = { id: nid, label: label.slice(0, 200), type: ntype };
  }

  function addEdge(a: string, b: string, relType: string, docId: string) {
    if (a === b || !a || !b) return;
    const key = a < b ? `${a}|${b}|${relType}` : `${b}|${a}|${relType}`;
    if (edgeSeen.has(key) || edges.length >= GRAPH_MAX_EDGES) return;
    edgeSeen.add(key);
    edges.push({
      source: a,
      target: b,
      relation_type: relType,
      doc_id: docId,
    });
  }

  for (const doc of sampleDocs) {
    const docId = doc.id;
    for (const rel of doc.relations || []) {
      const s = rel.source;
      const t = rel.target;
      if (!s || !t) continue;
      const sid = nodeId(String(s), "mention");
      const tid = nodeId(String(t), "mention");
      addNode(sid, String(s), "relation_endpoint");
      addNode(tid, String(t), "relation_endpoint");
      addEdge(sid, tid, rel.type || "related", docId);
      if (edges.length >= GRAPH_MAX_EDGES) break;
    }
    if (edges.length >= GRAPH_MAX_EDGES) break;

    const keyEnts: Array<[string, string]> = [];
    for (const e of doc.entities || []) {
      const et = e.type || "";
      if (!CO_OCC_TYPES.has(et)) continue;
      const raw = (e.canonical_value || e.value || "").trim();
      if (raw) keyEnts.push([et, raw]);
    }
    const cap = 15;
    const slice = keyEnts.slice(0, cap);
    for (let i = 0; i < slice.length; i++) {
      for (let j = i + 1; j < slice.length; j++) {
        const [t1, v1] = slice[i];
        const [t2, v2] = slice[j];
        if (v1 === v2 && t1 === t2) continue;
        const nid1 = nodeId(v1, t1);
        const nid2 = nodeId(v2, t2);
        addNode(nid1, v1, t1);
        addNode(nid2, v2, t2);
        addEdge(nid1, nid2, "co_occurs", docId);
        if (edges.length >= GRAPH_MAX_EDGES) break;
      }
      if (edges.length >= GRAPH_MAX_EDGES) break;
    }
  }

  const truncated =
    edges.length >= GRAPH_MAX_EDGES ||
    Object.keys(nodes).length >= GRAPH_MAX_NODES;

  return {
    nodes: Object.values(nodes),
    edges,
    truncated,
    doc_sample_size: sampleDocs.length,
  };
}
