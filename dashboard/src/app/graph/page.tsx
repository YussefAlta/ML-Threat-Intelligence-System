"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  type Connection,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Loader2, ArrowLeft } from "lucide-react";
import { IntelNode } from "@/components/graph/IntelNode";
import { graphSampleToFlow } from "@/lib/graph/layoutGraph";
import { buildClientGraph } from "@/lib/graph/buildClientGraph";
import type { GraphSample } from "@/lib/types";
import { useIntelligence } from "@/context/IntelligenceContext";

const nodeTypes = { intel: IntelNode };

export default function GraphPage() {
  const { docs, loading } = useIntelligence();
  const [fileSample, setFileSample] = useState<GraphSample | null>(null);
  const [sampleLoading, setSampleLoading] = useState(true);

  useEffect(() => {
    fetch(`/data/graph_sample.json?t=${Date.now()}`, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => setFileSample(data))
      .catch(() => setFileSample(null))
      .finally(() => setSampleLoading(false));
  }, []);

  const merged: GraphSample = useMemo(() => {
    if (fileSample && fileSample.nodes?.length) {
      return fileSample;
    }
    return buildClientGraph(docs);
  }, [fileSample, docs]);

  const [nodes, setNodes, onNodesChange] = useNodesState(
    graphSampleToFlow(merged).nodes,
  );
  const [edges, setEdges, onEdgesChange] = useEdgesState(
    graphSampleToFlow(merged).edges,
  );

  useEffect(() => {
    const { nodes: n, edges: e } = graphSampleToFlow(merged);
    setNodes(n);
    setEdges(e);
  }, [merged, setNodes, setEdges]);

  const onConnect = useCallback(
    (p: Connection) => setEdges((eds) => addEdge(p, eds)),
    [setEdges],
  );

  if (!sampleLoading && !loading && merged.nodes.length === 0) {
    return (
      <div className="min-h-[70vh] flex flex-col items-center justify-center text-slate-400 px-4">
        <p className="text-center mb-4">
          No graph data yet. Enrich the corpus and run{" "}
          <code className="text-cyan-400">prepare_dashboard_data.py</code>, or load
          enriched documents with entities/relations.
        </p>
        <Link href="/overview" className="text-cyan-400 hover:underline flex items-center gap-2">
          <ArrowLeft className="w-4 h-4" /> Back to command center
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-4 h-[calc(100vh-6rem)] flex flex-col">
      <div className="flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div>
          <Link
            href="/overview"
            className="text-xs text-slate-500 hover:text-cyan-400 mb-1 inline-flex items-center gap-1"
          >
            <ArrowLeft className="w-3 h-3" /> Command center
          </Link>
          <h1 className="text-xl font-bold text-slate-100">Entity relationship graph</h1>
          <p className="text-sm text-slate-500">
            {merged.nodes.length} nodes · {merged.edges.length} edges
            {merged.truncated ? " · sampled / truncated" : ""}
            {" · "}
            {merged.doc_sample_size} high-risk docs in sample
          </p>
        </div>
        {(sampleLoading || loading) && (
          <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
        )}
      </div>

      <div className="flex-1 min-h-[480px] rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          nodeTypes={nodeTypes}
          fitView
          className="bg-slate-950"
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#334155" gap={20} />
          <Controls className="!bg-slate-800 !border-slate-600" />
          <MiniMap
            className="!bg-slate-800 !border-slate-600"
            nodeColor={() => "#475569"}
          />
        </ReactFlow>
      </div>
    </div>
  );
}
