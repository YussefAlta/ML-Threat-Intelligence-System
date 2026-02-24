'use client';

import { useState, useEffect, useMemo } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Search, Filter, ChevronLeft, ChevronRight, Loader2, AlertTriangle } from 'lucide-react';
import {
  EnrichedDocument,
  CATEGORY_COLORS,
  SOURCE_COLORS,
  RiskTier,
} from '@/lib/types';

const SOURCES = ['exploitdb', 'ransomwatch', 'cisa_kev', 'nvd_ref', 'mitre_attack', 'phishtank', 'threatfox'];
const LABELS = ['vulnerability', 'exploit', 'phishing', 'ransomware', 'threat_actor', 'ioc'];
const RISK_TIERS: RiskTier[] = ['critical', 'high', 'medium', 'low'];
const PAGE_SIZE = 50;

export default function ThreatsPage() {
  const [docs, setDocs] = useState<EnrichedDocument[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [labelFilter, setLabelFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [page, setPage] = useState(1);

  useEffect(() => {
    fetch('/data/enriched.json')
      .then((r) => r.json())
      .then((data: EnrichedDocument[]) => {
        setDocs(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    let result = docs;
    if (search) {
      const q = search.toLowerCase();
      result = result.filter((d) => d.title.toLowerCase().includes(q));
    }
    if (sourceFilter) {
      result = result.filter((d) => d.source === sourceFilter);
    }
    if (labelFilter) {
      result = result.filter((d) => labelFilter in d.predicted_labels);
    }
    if (riskFilter) {
      result = result.filter((d) => d.risk_assessment.risk_tier === riskFilter);
    }
    return result;
  }, [docs, search, sourceFilter, labelFilter, riskFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pageData = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  useEffect(() => {
    setPage(1);
  }, [search, sourceFilter, labelFilter, riskFilter]);

  const riskBadgeClasses: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
    low: 'bg-green-500/20 text-green-400 border border-green-500/30',
  };

  const sourceBadgeStyle = (source: string) => {
    const color = SOURCE_COLORS[source] || '#64748b';
    return {
      backgroundColor: `${color}20`,
      color: color,
      border: `1px solid ${color}40`,
    };
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
        <span className="ml-3 text-slate-300 text-lg">Loading threat data...</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="max-w-[1600px] mx-auto px-6 py-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-3xl font-bold text-slate-100">Threat Feed</h1>
          <p className="text-slate-400 mt-1">
            {filtered.length.toLocaleString()} threats
            {filtered.length !== docs.length && ` (filtered from ${docs.length.toLocaleString()})`}
          </p>
        </motion.div>

        {/* Filter Panel */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="bg-slate-800 rounded-xl border border-slate-700 p-4 mb-6"
        >
          <div className="flex items-center gap-2 mb-3 text-slate-400 text-sm font-medium">
            <Filter className="w-4 h-4" />
            Filters
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            {/* Search */}
            <div className="lg:col-span-2 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search by title..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-10 pr-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:border-cyan-500/40"
              />
            </div>

            {/* Source */}
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:border-cyan-500/40"
            >
              <option value="">All Sources</option>
              {SOURCES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>

            {/* Label */}
            <select
              value={labelFilter}
              onChange={(e) => setLabelFilter(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:border-cyan-500/40"
            >
              <option value="">All Labels</option>
              {LABELS.map((l) => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>

            {/* Risk Tier */}
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:border-cyan-500/40"
            >
              <option value="">All Risk Tiers</option>
              {RISK_TIERS.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
        </motion.div>

        {/* Table */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
          className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden"
        >
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/80">
                  <th className="text-left px-4 py-3 text-slate-400 font-medium">Title</th>
                  <th className="text-left px-4 py-3 text-slate-400 font-medium w-28">Source</th>
                  <th className="text-left px-4 py-3 text-slate-400 font-medium w-48">Labels</th>
                  <th className="text-left px-4 py-3 text-slate-400 font-medium w-24">Risk</th>
                  <th className="text-right px-4 py-3 text-slate-400 font-medium w-24">Entities</th>
                </tr>
              </thead>
              <tbody>
                {pageData.map((doc, i) => {
                  const labels = Object.keys(doc.predicted_labels);
                  return (
                    <motion.tr
                      key={doc.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.01 }}
                    >
                      <td className="px-4 py-3 border-b border-slate-700/50">
                        <Link
                          href={`/threats/${doc.id}`}
                          className="text-slate-200 hover:text-cyan-400 transition-colors line-clamp-1"
                        >
                          {doc.title}
                        </Link>
                      </td>
                      <td className="px-4 py-3 border-b border-slate-700/50">
                        <span
                          className="inline-block px-2 py-0.5 rounded-md text-xs font-medium"
                          style={sourceBadgeStyle(doc.source)}
                        >
                          {doc.source}
                        </span>
                      </td>
                      <td className="px-4 py-3 border-b border-slate-700/50">
                        <div className="flex flex-wrap gap-1">
                          {labels.map((label) => (
                            <span
                              key={label}
                              className="inline-block px-2 py-0.5 rounded-md text-xs font-medium"
                              style={{
                                backgroundColor: `${CATEGORY_COLORS[label] || '#64748b'}20`,
                                color: CATEGORY_COLORS[label] || '#94a3b8',
                                border: `1px solid ${CATEGORY_COLORS[label] || '#64748b'}40`,
                              }}
                            >
                              {label}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 border-b border-slate-700/50">
                        <span
                          className={`inline-block px-2 py-0.5 rounded-md text-xs font-semibold uppercase ${riskBadgeClasses[doc.risk_assessment.risk_tier]}`}
                        >
                          {doc.risk_assessment.risk_tier}
                        </span>
                      </td>
                      <td className="px-4 py-3 border-b border-slate-700/50 text-right text-slate-300 font-mono">
                        {doc.entity_summary.total}
                      </td>
                    </motion.tr>
                  );
                })}
                {pageData.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-12 text-center text-slate-500">
                      <AlertTriangle className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                      No threats match the current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700 bg-slate-800/50">
              <p className="text-sm text-slate-400">
                Showing {((currentPage - 1) * PAGE_SIZE + 1).toLocaleString()}
                {' '}&ndash;{' '}
                {Math.min(currentPage * PAGE_SIZE, filtered.length).toLocaleString()}
                {' '}of {filtered.length.toLocaleString()}
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className="p-2 rounded-lg border border-slate-700 text-slate-400 hover:text-slate-200 hover:bg-slate-700 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <span className="text-sm text-slate-300 min-w-[80px] text-center">
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  className="p-2 rounded-lg border border-slate-700 text-slate-400 hover:text-slate-200 hover:bg-slate-700 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </motion.div>
      </div>
    </div>
  );
}
