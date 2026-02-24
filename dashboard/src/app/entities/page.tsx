'use client';

import { useState, useEffect, useMemo } from 'react';
import { motion } from 'framer-motion';
import { Search, ChevronLeft, ChevronRight, Loader2, Database, ArrowUpDown } from 'lucide-react';
import { EnrichedDocument } from '@/lib/types';

interface AggregatedEntity {
  type: string;
  value: string;
  count: number;
  methods: Set<string>;
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
};

const PAGE_SIZE = 100;

export default function EntitiesPage() {
  const [docs, setDocs] = useState<EnrichedDocument[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [page, setPage] = useState(1);
  const [sortField, setSortField] = useState<'count' | 'value' | 'type'>('count');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

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
      for (const ent of doc.entities) {
        const displayValue = ent.canonical_value || ent.value;
        const key = `${ent.type}::${displayValue}`;
        typesSet.add(ent.type);

        const existing = map.get(key);
        if (existing) {
          existing.count++;
          existing.methods.add(ent.method);
        } else {
          map.set(key, {
            type: ent.type,
            value: displayValue,
            count: 1,
            methods: new Set([ent.method]),
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

  useEffect(() => {
    setPage(1);
  }, [search, typeFilter, sortField, sortDir]);

  const toggleSort = (field: 'count' | 'value' | 'type') => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir(field === 'count' ? 'desc' : 'asc');
    }
  };

  const SortIcon = ({ field }: { field: string }) => (
    <ArrowUpDown
      className={`w-3 h-3 ml-1 inline-block ${
        sortField === field ? 'text-cyan-400' : 'text-slate-600'
      }`}
    />
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
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-3xl font-bold text-slate-100 flex items-center gap-3">
            <Database className="w-8 h-8 text-cyan-400" />
            Entity Explorer
          </h1>
          <p className="text-slate-400 mt-1">
            {filtered.length.toLocaleString()} unique entities
            {filtered.length !== aggregated.length && ` (filtered from ${aggregated.length.toLocaleString()})`}
          </p>
        </motion.div>

        {/* Filters */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="bg-slate-800 rounded-xl border border-slate-700 p-4 mb-6"
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search entities..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-10 pr-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:border-cyan-500/40"
              />
            </div>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:border-cyan-500/40"
            >
              <option value="">All Entity Types</option>
              {entityTypes.map((t) => (
                <option key={t} value={t}>{t}</option>
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
                  <th
                    className="text-left px-4 py-3 text-slate-400 font-medium cursor-pointer hover:text-slate-200 transition-colors select-none"
                    onClick={() => toggleSort('value')}
                  >
                    Entity Value <SortIcon field="value" />
                  </th>
                  <th
                    className="text-left px-4 py-3 text-slate-400 font-medium w-32 cursor-pointer hover:text-slate-200 transition-colors select-none"
                    onClick={() => toggleSort('type')}
                  >
                    Type <SortIcon field="type" />
                  </th>
                  <th
                    className="text-right px-4 py-3 text-slate-400 font-medium w-28 cursor-pointer hover:text-slate-200 transition-colors select-none"
                    onClick={() => toggleSort('count')}
                  >
                    Frequency <SortIcon field="count" />
                  </th>
                  <th className="text-left px-4 py-3 text-slate-400 font-medium w-28">Method</th>
                </tr>
              </thead>
              <tbody>
                {pageData.map((ent, i) => {
                  const typeClass = ENTITY_TYPE_COLORS[ent.type] || 'bg-slate-500/20 text-slate-400 border-slate-500/30';
                  return (
                    <tr
                      key={`${ent.type}-${ent.value}-${i}`}
                      className={i % 2 === 0 ? 'bg-slate-800/30' : 'bg-slate-800/60'}
                    >
                      <td className="px-4 py-2.5 border-b border-slate-700/30">
                        <span className="text-slate-200 font-mono text-xs break-all">{ent.value}</span>
                      </td>
                      <td className="px-4 py-2.5 border-b border-slate-700/30">
                        <span className={`inline-block px-2 py-0.5 rounded-md text-xs font-medium border ${typeClass}`}>
                          {ent.type}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 border-b border-slate-700/30 text-right text-slate-300 font-mono">
                        {ent.count.toLocaleString()}
                      </td>
                      <td className="px-4 py-2.5 border-b border-slate-700/30">
                        <div className="flex gap-1">
                          {Array.from(ent.methods).map((method) => (
                            <span
                              key={method}
                              className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                                method === 'regex'
                                  ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                                  : 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                              }`}
                            >
                              {method}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {pageData.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-4 py-12 text-center text-slate-500">
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
