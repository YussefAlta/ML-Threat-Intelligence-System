import type { Edge, Node } from "@xyflow/react";
import type { GraphSample } from "@/lib/types";

const TYPE_COLORS: Record<string, string> = {
  cve_id: "#f87171",
  domain: "#4ade80",
  malware: "#f472b6",
  organization: "#818cf8",
  ipv4: "#38bdf8",
  ipv6: "#38bdf8",
  relation_endpoint: "#94a3b8",
  default: "#64748b",
};

export function graphSampleToFlow(sample: GraphSample): {
  nodes: Node[];
  edges: Edge[];
} {
  const n = sample.nodes.length;
  const radius = Math.max(280, 50 * Math.sqrt(n + 1));

  const nodes: Node[] = sample.nodes.map((node, i) => {
    const angle = (2 * Math.PI * i) / Math.max(n, 1);
    const x = radius + Math.cos(angle) * radius * 0.85;
    const y = radius + Math.sin(angle) * radius * 0.85;
    const color = TYPE_COLORS[node.type] ?? TYPE_COLORS.default;
    return {
      id: node.id,
      type: "intel",
      position: { x, y },
      data: {
        label: node.label || node.type,
        sublabel: node.type,
        color,
      },
    };
  });

  const edges: Edge[] = sample.edges.map((e, i) => ({
    id: `e-${i}-${e.source}-${e.target}`,
    source: e.source,
    target: e.target,
    label: e.relation_type,
    style: { stroke: "#475569", strokeWidth: 1 },
    labelStyle: { fill: "#94a3b8", fontSize: 10 },
  }));

  return { nodes, edges };
}
