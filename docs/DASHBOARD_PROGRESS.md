# Dashboard: Command Center Progress Summary

This document records the work completed to evolve the Next.js dashboard into a centralized **command center** with abstract threat visualizations, time-series trends, an entity relationship graph, and an in-app **rule-based alert** feed.

## Goals Delivered

1. **Centralized intelligence view** — Single hub at `/overview` (home `/` redirects here) combining KPIs, pipeline view, alerts, landscape charts, trends, and navigation to deeper views.
2. **Abstract threat landscape** — Treemap by OSINT source; bar charts for risk tiers and threat categories (not geographic).
3. **Trend graphs** — Document volume over time and stacked risk mix, driven by precomputed `stats.trends` when timestamps exist on enriched docs.
4. **Entity relationship diagram** — `/graph` with React Flow; uses server-built `graph_sample.json` when present, otherwise client-side `buildClientGraph()` (relations plus co-occurrence fallback, size-capped).
5. **Alerts** — Declarative rules, evaluation over loaded `enriched.json`, dismissals in `localStorage`, optional browser notifications, sidebar badge count, ~2-minute background refetch of static data.

## Pipeline and Data Changes

### NLP enricher (`src/threat_intelligence/nlp/nlp_enricher.py`)

- Preserves corpus **provenance** on each enriched document: `published_at`, `collected_at`, `url`, and a **trimmed** `metadata` object (e.g. `cve_id`, `cvss`, `cwe_ids`) for dashboard rules and trends.

### Dashboard data prep (`scripts/prepare_dashboard_data.py`)

- **`stats.trends`**: Last-window (default 90 days) aggregates — `documents_by_day`, `by_source_by_day`, `by_risk_by_day`.
- **`dashboard/public/data/graph_sample.json`**: Capped subgraph (high-risk doc sample, relation-first edges, co-occurrence fallback) aligned with client logic.

### Git ignore fix (`.gitignore`)

- Replaced bare `lib/` with root-only **`/lib/`** so **`dashboard/src/lib/`** is not ignored (the bare pattern unintentionally excluded shared TypeScript modules).

## Dashboard Application (`dashboard/`)

### New or updated dependencies

- `@xyflow/react` — interactive entity graph.

### Routing and shell

- **`/`** — Server redirect to **`/overview`**.
- **`/overview`** — Command center page.
- **`/graph`** — Full-page entity graph.
- **`/alerts`** — Extended alert list.
- **`AppShell`** + **`IntelligenceProvider`** — Wraps sidebar and main content; loads `stats.json` and `enriched.json`, polling, dismiss state, optional notifications.

### UI components

- **`AlertFeed`** — Rule filter, dismiss, links to `/threats/[id]`, browser alert toggle.
- **`ThreatLandscape`** — Recharts treemap + bar charts.
- **`TrendCharts`** — Line + stacked area from `stats.trends` (graceful empty state when trends absent).
- **`IntelNode`** — Custom React Flow node.
- **`Sidebar`** — Command center, graph, alerts (with badge), existing sections.

### Shared modules (`dashboard/src/lib/`)

- **`types.ts`** — `TrendsBlock`, `GraphSample*`, optional provenance on `EnrichedDocument`, `EnrichedMetadata`.
- **`alerts/rules.ts`**, **`alerts/engine.ts`** — Rule definitions and `evaluateAlerts()`.
- **`graph/layoutGraph.ts`**, **`graph/buildClientGraph.ts`** — Flow layout and client graph build.

### Static assets

- **`public/data/graph_sample.json`** — Placeholder (empty graph) until `prepare_dashboard_data.py` is run on enriched JSONL.

## How to Regenerate Live Dashboard Data

From the **repository root** (after NLP enriched JSONL exists under `data/processed/`):

```bash
python scripts/prepare_dashboard_data.py
```

This refreshes `dashboard/public/data/enriched.json`, `stats.json` (including `trends`), and `graph_sample.json`.

## How to Run the Dashboard Locally

```bash
cd dashboard
npm install
npm run dev
```

Open the URL shown in the terminal (often `http://localhost:3000`; another port is used if 3000 is busy).

## Verification

- `npm run build` in `dashboard/` completes successfully (production typecheck + compile).

## Known Limitations

- “Real-time” is **polling** of static files, not WebSockets or push.
- **Large `enriched.json`** can be heavy in the browser; graph uses sampling caps.
- **`stats.json`** in the repo may omit `trends` until `prepare_dashboard_data.py` is run on data with `collected_at` / `published_at` (or fallback `enriched_at`).

---

*CYSE / AVINT threat intelligence dashboard — Spring 2026 iteration.*
