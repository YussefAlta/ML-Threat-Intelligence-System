'use client';

import { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, ChevronLeft, ChevronRight, Loader2, Database,
  ArrowUpDown, ChevronDown, ExternalLink, ShieldAlert, FileText,
} from 'lucide-react';
import Link from 'next/link';
import { EnrichedDocument, CATEGORY_COLORS, SOURCE_COLORS } from '@/lib/types';

interface DocReference {
  id: string;
  title: string;
  source: string;
  labels: string[];
  risk_tier: string;
  risk_score: number;
}

interface AggregatedEntity {
  type: string;
  value: string;
  count: number;
  methods: Set<string>;
  docs: DocReference[];
  sources: Set<string>;
  labels: Set<string>;
  riskTiers: Record<string, number>;
}

const ENTITY_TYPE_COLORS: Record<string, string> = {
  cve_id: 'bg-red-500/20 text-red-400 border-red-500/30',
  ipv4: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  ipv6: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  domain: 'bg-green-500/20 text-green-400 border-green-500/30',
  url: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  email: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  cvss_score: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  md5: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  sha1: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  sha256: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  malware: 'bg-red-500/20 text-red-400 border-red-500/30',
  organization: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
  system: 'bg-teal-500/20 text-teal-400 border-teal-500/30',
  indicator: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  vulnerability: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
};

const RISK_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-green-500/20 text-green-400 border-green-500/30',
};

const PAGE_SIZE = 50;

export default function EntitiesPage() {
  const [docs, setDocs] = useState<EnrichedDocument[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [page, setPage] = useState(1);
  const [sortField, setSortField] = useState<'count' | 'value' | 'type'>('count');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [expandedEntity, setExpandedEntity] = useState<string | null>(null);

  useEffect(() => {
    fetch('/data/enriched.json')
      .then((r) => r.json())
      .then((data: EnrichedDocument[]) => {
        setDocs(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const { aggregated, entityTypes } = useMemo(() => {
    const map = new Map<string, AggregatedEntity>();
    const typesSet = new Set<string>();

    for (const doc of docs) {
      const docRef: DocReference = {
        id: doc.id,
        title: doc.title,
        source: doc.source,
        labels: Object.keys(doc.predicted_labels || {}),
        risk_tier: doc.risk_assessment?.risk_tier || 'low',
        risk_score: doc.risk_assessment?.risk_score || 0,
      };

      for (const ent of doc.entities) {
        const displayValue = ent.canonical_value || ent.value;
        const key = `${ent.type}::${displayValue}`;
        typesSet.add(ent.type);

        const existing = map.get(key);
        if (existing) {
          existing.count++;
          existing.methods.add(ent.method);
          existing.sources.add(doc.source);
          for (const l of docRef.labels) existing.labels.add(l);
          existing.riskTiers[docRef.risk_tier] = (existing.riskTiers[docRef.risk_tier] || 0) + 1;
          if (!existing.docs.find((d) => d.id === doc.id)) {
            existing.docs.push(docRef);
          }
        } else {
          map.set(key, {
            type: ent.type,
            value: displayValue,
            count: 1,
            methods: new Set([ent.method]),
            docs: [docRef],
            sources: new Set([doc.source]),
            labels: new Set(docRef.labels),
            riskTiers: { [docRef.risk_tier]: 1 },
          });
        }
      }
    }

    return {
      aggregated: Array.from(map.values()),
      entityTypes: Array.from(typesSet).sort(),
    };
  }, [docs]);

  const filtered = useMemo(() => {
    let result = aggregated;
    if (search) {
      const q = search.toLowerCase();
      result = result.filter((e) => e.value.toLowerCase().includes(q));
    }
    if (typeFilter) {
      result = result.filter((e) => e.type === typeFilter);
    }
    result.sort((a, b) => {
      let cmp = 0;
      if (sortField === 'count') cmp = a.count - b.count;
      else if (sortField === 'value') cmp = a.value.localeCompare(b.value);
      else cmp = a.type.localeCompare(b.type);
      return sortDir === 'desc' ? -cmp : cmp;
    });
    return result;
  }, [aggregated, search, typeFilter, sortField, sortDir]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pageData = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  useEffect(() => { setPage(1); }, [search, typeFilter, sortField, sortDir]);

  const toggleSort = (field: 'count' | 'value' | 'type') => {
    if (sortField === field) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortField(field); setSortDir(field === 'count' ? 'desc' : 'asc'); }
  };

  const SortIcon = ({ field }: { field: string }) => (
    <ArrowUpDown className={`w-3 h-3 ml-1 inline-block ${sortField === field ? 'text-cyan-400' : 'text-slate-600'}`} />
  );

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
        <span className="ml-3 text-slate-300 text-lg">Loading entity data...</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="max-w-[1400px] mx-auto px-6 py-8">
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="mb-8">
          <h1 className="text-3xl font-bold text-slate-100 flex items-center gap-3">
            <Database className="w-8 h-8 text-cyan-400" />
            Entity Explorer
          </h1>
          <p className="text-slate-400 mt-1">
            {filtered.length.toLocaleString()} unique entities across {docs.length.toLocaleString()} documents
            {filtered.length !== aggregated.length && ` (filtered from ${aggregated.length.toLocaleString()})`}
          </p>
        </motion.div>

        {/* Filters */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}
          className="bg-slate-800 rounded-xl border border-slate-700 p-4 mb-6"
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input type="text" placeholder="Search entities..." value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-10 pr-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
              />
            </div>
            <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
            >
              <option value="">All Entity Types</option>
              {entityTypes.map((t) => (<option key={t} value={t}>{t}</option>))}
            </select>
          </div>
        </motion.div>

        {/* Table */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}
          className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden"
        >
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/80">
                  <th className="w-8 px-2 py-3"></th>
                  <th className="text-left px-4 py-3 text-slate-400 font-medium cursor-pointer hover:text-slate-200 select-none"
                    onClick={() => toggleSort('value')}>
                    Entity Value <SortIcon field="value" />
                  </th>
                  <th className="text-left px-4 py-3 text-slate-400 font-medium w-32 cursor-pointer hover:text-slate-200 select-none"
                    onClick={() => toggleSort('type')}>
                    Type <SortIcon field="type" />
                  </th>
                  <th className="text-left px-4 py-3 text-slate-400 font-medium w-40">Found In</th>
                  <th className="text-left px-4 py-3 text-slate-400 font-medium w-40">Categories</th>
                  <th className="text-right px-4 py-3 text-slate-400 font-medium w-24 cursor-pointer hover:text-slate-200 select-none"
                    onClick={() => toggleSort('count')}>
                    Freq <SortIcon field="count" />
                  </th>
                  <th className="text-left px-4 py-3 text-slate-400 font-medium w-24">Method</th>
                </tr>
              </thead>
              <tbody>
                {pageData.map((ent, i) => {
                  const key = `${ent.type}::${ent.value}`;
                  const isExpanded = expandedEntity === key;
                  const typeClass = ENTITY_TYPE_COLORS[ent.type] || 'bg-slate-500/20 text-slate-400 border-slate-500/30';
                  const topSources = Array.from(ent.sources).slice(0, 3);
                  const topLabels = Array.from(ent.labels).slice(0, 3);

                  return (
                    <tbody key={key + i}>
                      <tr
                        className={`cursor-pointer transition-colors ${isExpanded ? 'bg-slate-700/40' : i % 2 === 0 ? 'bg-slate-800/30 hover:bg-slate-700/20' : 'bg-slate-800/60 hover:bg-slate-700/20'}`}
                        onClick={() => setExpandedEntity(isExpanded ? null : key)}
                      >
                        <td className="px-2 py-2.5 border-b border-slate-700/30">
                          <ChevronDown className={`w-4 h-4 text-slate-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                        </td>
                        <td className="px-4 py-2.5 border-b border-slate-700/30">
                          <span className="text-slate-200 font-mono text-xs break-all">{ent.value}</span>
                        </td>
                        <td className="px-4 py-2.5 border-b border-slate-700/30">
                          <span className={`inline-block px-2 py-0.5 rounded-md text-xs font-medium border ${typeClass}`}>
                            {ent.type}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 border-b border-slate-700/30">
                          <div className="flex flex-wrap gap-1">
                            {topSources.map((s) => (
                              <span key={s} className="text-[10px] px-1.5 py-0.5 rounded border border-slate-600 text-slate-400"
                                style={{ borderColor: SOURCE_COLORS[s] || '#475569', color: SOURCE_COLORS[s] || '#94a3b8' }}>
                                {s}
                              </span>
                            ))}
                            {ent.sources.size > 3 && (
                              <span className="text-[10px] px-1.5 py-0.5 text-slate-500">+{ent.sources.size - 3}</span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-2.5 border-b border-slate-700/30">
                          <div className="flex flex-wrap gap-1">
                            {topLabels.map((l) => (
                              <span key={l} className="text-[10px] px-1.5 py-0.5 rounded font-medium"
                                style={{ backgroundColor: (CATEGORY_COLORS[l] || '#475569') + '33', color: CATEGORY_COLORS[l] || '#94a3b8' }}>
                                {l}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="px-4 py-2.5 border-b border-slate-700/30 text-right text-slate-300 font-mono">
                          {ent.count.toLocaleString()}
                        </td>
                        <td className="px-4 py-2.5 border-b border-slate-700/30">
                          <div className="flex gap-1">
                            {Array.from(ent.methods).map((method) => (
                              <span key={method}
                                className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${method === 'regex' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' : 'bg-purple-500/20 text-purple-400 border border-purple-500/30'}`}>
                                {method}
                              </span>
                            ))}
                          </div>
                        </td>
                      </tr>

                      {/* Expanded detail panel */}
                      <AnimatePresence>
                        {isExpanded && (
                          <tr>
                            <td colSpan={7} className="p-0">
                              <motion.div
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: 'auto', opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                                transition={{ duration: 0.2 }}
                                className="overflow-hidden"
                              >
                                <div className="bg-slate-900/50 border-b border-slate-700/30 px-6 py-4">
                                  {/* Summary row */}
                                  <div className="flex flex-wrap gap-6 mb-4">
                                    <div>
                                      <p className="text-[10px] uppercase text-slate-500 mb-1">Documents</p>
                                      <p className="text-lg font-mono text-cyan-400">{ent.docs.length}</p>
                                    </div>
                                    <div>
                                      <p className="text-[10px] uppercase text-slate-500 mb-1">Occurrences</p>
                                      <p className="text-lg font-mono text-slate-200">{ent.count}</p>
                                    </div>
                                    <div>
                                      <p className="text-[10px] uppercase text-slate-500 mb-1">Sources</p>
                                      <div className="flex flex-wrap gap-1 mt-1">
                                        {Array.from(ent.sources).map((s) => (
                                          <span key={s} className="text-xs px-2 py-0.5 rounded border"
                                            style={{ borderColor: SOURCE_COLORS[s] || '#475569', color: SOURCE_COLORS[s] || '#94a3b8' }}>
                                            {s}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                    <div>
                                      <p className="text-[10px] uppercase text-slate-500 mb-1">Threat Categories</p>
                                      <div className="flex flex-wrap gap-1 mt-1">
                                        {Array.from(ent.labels).map((l) => (
                                          <span key={l} className="text-xs px-2 py-0.5 rounded font-medium"
                                            style={{ backgroundColor: (CATEGORY_COLORS[l] || '#475569') + '33', color: CATEGORY_COLORS[l] || '#94a3b8' }}>
                                            {l}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                    <div>
                                      <p className="text-[10px] uppercase text-slate-500 mb-1">Risk Breakdown</p>
                                      <div className="flex gap-2 mt-1">
                                        {(['critical', 'high', 'medium', 'low'] as const).map((tier) => {
                                          const ct = ent.riskTiers[tier] || 0;
                                          if (ct === 0) return null;
                                          return (
                                            <span key={tier} className={`text-xs px-2 py-0.5 rounded border font-mono ${RISK_BADGE[tier]}`}>
                                              {tier}: {ct}
                                            </span>
                                          );
                                        })}
                                      </div>
                                    </div>
                                  </div>

                                  {/* Document list */}
                                  <p className="text-[10px] uppercase text-slate-500 mb-2 flex items-center gap-1">
                                    <FileText className="w-3 h-3" />
                                    Documents containing this entity ({Math.min(ent.docs.length, 10)} of {ent.docs.length})
                                  </p>
                                  <div className="space-y-1.5">
                                    {ent.docs.slice(0, 10).map((doc) => (
                                      <Link
                                        key={doc.id}
                                        href={`/threats/${doc.id}`}
                                        className="flex items-center gap-3 px-3 py-2 rounded-lg bg-slate-800/60 hover:bg-slate-700/40 border border-slate-700/30 transition-colors group"
                                      >
                                        <ShieldAlert className="w-4 h-4 text-slate-500 flex-shrink-0" />
                                        <span className="text-xs text-slate-300 truncate flex-1 group-hover:text-cyan-400 transition-colors">
                                          {doc.title}
                                        </span>
                                        <span className="text-[10px] px-1.5 py-0.5 rounded border flex-shrink-0"
                                          style={{ borderColor: SOURCE_COLORS[doc.source] || '#475569', color: SOURCE_COLORS[doc.source] || '#94a3b8' }}>
                                          {doc.source}
                                        </span>
                                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium flex-shrink-0 ${RISK_BADGE[doc.risk_tier] || ''}`}>
                                          {doc.risk_tier}
                                        </span>
                                        {doc.labels.map((l) => (
                                          <span key={l} className="text-[10px] px-1.5 py-0.5 rounded font-medium flex-shrink-0"
                                            style={{ backgroundColor: (CATEGORY_COLORS[l] || '#475569') + '33', color: CATEGORY_COLORS[l] || '#94a3b8' }}>
                                            {l}
                                          </span>
                                        ))}
                                        <ExternalLink className="w-3 h-3 text-slate-600 group-hover:text-cyan-400 flex-shrink-0" />
                                      </Link>
                                    ))}
                                    {ent.docs.length > 10 && (
                                      <p className="text-xs text-slate-500 px-3 py-1">
                                        and {ent.docs.length - 10} more documents...
                                      </p>
                                    )}
                                  </div>
                                </div>
                              </motion.div>
                            </td>
                          </tr>
                        )}
                      </AnimatePresence>
                    </tbody>
                  );
                })}
                {pageData.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-slate-500">
                      No entities match the current filters.
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
                <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={currentPage === 1}
                  className="p-2 rounded-lg border border-slate-700 text-slate-400 hover:text-slate-200 hover:bg-slate-700 disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <span className="text-sm text-slate-300 min-w-[80px] text-center">
                  Page {currentPage} of {totalPages}
                </span>
                <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}
                  className="p-2 rounded-lg border border-slate-700 text-slate-400 hover:text-slate-200 hover:bg-slate-700 disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
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
