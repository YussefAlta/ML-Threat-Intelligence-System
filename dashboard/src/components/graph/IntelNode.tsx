"use client";

import { Handle, Position, type NodeProps } from "@xyflow/react";

type IntelData = {
  label: string;
  sublabel?: string;
  color?: string;
};

export function IntelNode(props: NodeProps) {
  const data = props.data as IntelData;
  const border = data.color ?? "#64748b";
  return (
    <div
      className="rounded-lg px-2 py-1.5 min-w-[100px] max-w-[180px] bg-slate-900/95 border shadow-lg text-left"
      style={{ borderColor: border }}
    >
      <Handle
        type="target"
        position={Position.Top}
        className="!bg-slate-500 !w-2 !h-2"
      />
      <p className="text-[11px] text-slate-100 font-medium truncate" title={data.label}>
        {data.label}
      </p>
      {data.sublabel && (
        <p className="text-[9px] text-slate-500 uppercase tracking-wide truncate">
          {data.sublabel}
        </p>
      )}
      <Handle
        type="source"
        position={Position.Bottom}
        className="!bg-slate-500 !w-2 !h-2"
      />
    </div>
  );
}
