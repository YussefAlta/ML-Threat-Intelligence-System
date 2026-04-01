"use client";

import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { AlertFeed } from "@/components/AlertFeed";

export default function AlertsPage() {
  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <Link
          href="/overview"
          className="text-xs text-slate-500 hover:text-cyan-400 mb-2 inline-flex items-center gap-1"
        >
          <ArrowLeft className="w-3 h-3" /> Command center
        </Link>
        <h1 className="text-2xl font-bold text-slate-100">Alerts</h1>
        <p className="text-sm text-slate-500 mt-1">
          Rule-based priorities on the current intelligence snapshot. Data refreshes
          periodically when static exports are updated.
        </p>
      </div>
      <AlertFeed maxItems={500} />
    </div>
  );
}
