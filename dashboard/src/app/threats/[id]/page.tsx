'use client';

import { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { motion } from 'framer-motion';
import {
  ArrowLeft,
  Loader2,
  Shield,
  Bug,
  Globe,
  Hash,
  Mail,
  Link as LinkIcon,
  AlertTriangle,
  Network,
  FileWarning,
} from 'lucide-react';
import {
  EnrichedDocument,
  CATEGORY_COLORS,
  SOURCE_COLORS,
  RISK_COLORS,
} from '@/lib/types';

const entityTypeIcons: Record<string, React.ReactNode> = {
  cve_id: <Bug className="w-4 h-4" />,
  ipv4: <Network className="w-4 h-4" />,
  ipv6: <Network className="w-4 h-4" />,
  domain: <Globe className="w-4 h-4" />,
  url: <LinkIcon className="w-4 h-4" />,
  email: <Mail className="w-4 h-4" />,
  md5: <Hash className="w-4 h-4" />,
  sha1: <Hash className="w-4 h-4" />,
  sha256: <Hash className="w-4 h-4" />,
  cvss_score: <Shield className="w-4 h-4" />,
};

export default function ThreatDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const [doc, setDoc] = useState<EnrichedDocument | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    fetch('/data/enriched.json')
      .then((r) => r.json())
      .then((data: EnrichedDocument[]) => {
        const found = data.find((d) => d.id === id);
        if (found) {
          setDoc(found);
        } else {
          setNotFound(true);
        }
        setLoading(false);
      })
      .catch(() => {
        setNotFound(true);
        setLoading(false);
      });
  }, [id]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
        <span className="ml-3 text-slate-300 text-lg">Loading threat details...</span>
      </div>
    );
  }

  if (notFound || !doc) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400">
        <FileWarning className="w-16 h-16 mb-4 text-slate-600" />
        <h2 className="text-xl font-semibold text-slate-200 mb-2">Threat Not Found</h2>
        <p className="mb-6">No document found with ID: {id}</p>
        <Link
          href="/threats"
          className="flex items-center gap-2 text-cyan-400 hover:text-cyan-300 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Threat Feed
        </Link>
      </div>
    );
  }

  const riskBadgeClasses: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
    low: 'bg-green-500/20 text-green-400 border border-green-500/30',
  };

  const labels = Object.keys(doc.predicted_labels);
  const sourceColor = SOURCE_COLORS[doc.source] || '#64748b';

  // Group entities by type
  const entitiesByType: Record<string, typeof doc.entities> = {};
  doc.entities.forEach((ent) => {
    if (!entitiesByType[ent.type]) entitiesByType[ent.type] = [];
    entitiesByType[ent.type].push(ent);
  });

  const summaryCards = [
    { label: 'CVEs', value: doc.entity_summary.unique_cves.length, icon: <Bug className="w-5 h-5" />, color: 'text-red-400' },
    { label: 'IPs', value: doc.entity_summary.unique_ips.length, icon: <Network className="w-5 h-5" />, color: 'text-blue-400' },
    { label: 'Domains', value: doc.entity_summary.unique_domains.length, icon: <Globe className="w-5 h-5" />, color: 'text-green-400' },
    {
      label: 'Hashes',
      value:
        doc.entity_summary.unique_hashes.md5.length +
        doc.entity_summary.unique_hashes.sha1.length +
        doc.entity_summary.unique_hashes.sha256.length,
      icon: <Hash className="w-5 h-5" />,
      color: 'text-purple-400',
    },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="max-w-[1200px] mx-auto px-6 py-8">
        {/* Back Link */}
        <Link
          href="/threats"
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-400 transition-colors mb-6"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Threat Feed
        </Link>

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-2xl font-bold text-slate-100 mb-3 leading-tight">{doc.title}</h1>
          <div className="flex flex-wrap items-center gap-2">
            <span
              className="inline-block px-2.5 py-1 rounded-md text-xs font-medium"
              style={{
                backgroundColor: `${sourceColor}20`,
                color: sourceColor,
                border: `1px solid ${sourceColor}40`,
              }}
            >
              {doc.source}
            </span>
            <span
              className={`inline-block px-2.5 py-1 rounded-md text-xs font-semibold uppercase ${riskBadgeClasses[doc.risk_assessment.risk_tier]}`}
            >
              {doc.risk_assessment.risk_tier}
            </span>
            {labels.map((label) => (
              <span
                key={label}
                className="inline-block px-2.5 py-1 rounded-md text-xs font-medium"
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
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Risk Assessment */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 }}
            className="lg:col-span-1 bg-slate-800 rounded-xl border border-slate-700 p-6"
          >
            <h2 className="text-lg font-semibold text-slate-200 mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              Risk Assessment
            </h2>

            {/* Risk Score Bar */}
            <div className="mb-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-400">Risk Score</span>
                <span className="text-sm font-mono font-bold" style={{ color: RISK_COLORS[doc.risk_assessment.risk_tier] }}>
                  {(doc.risk_assessment.risk_score * 100).toFixed(1)}%
                </span>
              </div>
              <div className="w-full h-3 bg-slate-900 rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${doc.risk_assessment.risk_score * 100}%` }}
                  transition={{ duration: 0.8, ease: 'easeOut' }}
                  className="h-full rounded-full"
                  style={{ backgroundColor: RISK_COLORS[doc.risk_assessment.risk_tier] }}
                />
              </div>
            </div>

            {/* Tier Badge */}
            <div className="mb-5">
              <span
                className={`inline-block px-3 py-1.5 rounded-lg text-sm font-bold uppercase ${riskBadgeClasses[doc.risk_assessment.risk_tier]}`}
              >
                {doc.risk_assessment.risk_tier} Risk
              </span>
            </div>

            {/* Contributing Factors */}
            {doc.risk_assessment.contributing_factors.length > 0 && (
              <div>
                <h3 className="text-sm font-medium text-slate-400 mb-2">Contributing Factors</h3>
                <ul className="space-y-1.5">
                  {doc.risk_assessment.contributing_factors.map((factor, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                      <AlertTriangle className="w-3.5 h-3.5 mt-0.5 text-yellow-500 shrink-0" />
                      {factor}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </motion.div>

          {/* Entity Summary Cards */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="lg:col-span-2"
          >
            <h2 className="text-lg font-semibold text-slate-200 mb-4">Entity Summary</h2>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
              {summaryCards.map((card) => (
                <div
                  key={card.label}
                  className="bg-slate-800 rounded-xl border border-slate-700 p-4 text-center"
                >
                  <div className={`flex justify-center mb-2 ${card.color}`}>{card.icon}</div>
                  <p className="text-2xl font-bold text-slate-100">{card.value}</p>
                  <p className="text-xs text-slate-400 mt-1">{card.label}</p>
                </div>
              ))}
            </div>

            {/* Entities by Type */}
            <div className="space-y-4">
              {Object.entries(entitiesByType).map(([type, entities]) => (
                <div
                  key={type}
                  className="bg-slate-800 rounded-xl border border-slate-700 p-4"
                >
                  <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2 uppercase tracking-wide">
                    {entityTypeIcons[type] || <Hash className="w-4 h-4" />}
                    {type}
                    <span className="text-xs text-slate-500 font-normal lowercase">({entities.length})</span>
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {entities.map((ent, i) => (
                      <div
                        key={`${ent.value}-${i}`}
                        className="flex items-center gap-2 bg-slate-900 rounded-lg px-3 py-1.5 border border-slate-700"
                      >
                        <span className="text-sm text-slate-200 font-mono break-all max-w-[300px] truncate">
                          {ent.canonical_value || ent.value}
                        </span>
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                            ent.method === 'regex'
                              ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                              : 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                          }`}
                        >
                          {ent.method}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </div>

        {/* Relations */}
        {doc.relations.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15 }}
            className="mt-6 bg-slate-800 rounded-xl border border-slate-700 p-6"
          >
            <h2 className="text-lg font-semibold text-slate-200 mb-4 flex items-center gap-2">
              <Network className="w-5 h-5 text-cyan-400" />
              Relations
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="text-left px-4 py-2.5 text-slate-400 font-medium">Source</th>
                    <th className="text-left px-4 py-2.5 text-slate-400 font-medium">Type</th>
                    <th className="text-left px-4 py-2.5 text-slate-400 font-medium">Target</th>
                    <th className="text-left px-4 py-2.5 text-slate-400 font-medium">Confidence</th>
                    <th className="text-left px-4 py-2.5 text-slate-400 font-medium">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {doc.relations.map((rel, i) => (
                    <tr key={i} className="border-b border-slate-700/50">
                      <td className="px-4 py-2.5 text-slate-200 font-mono text-xs">{rel.source}</td>
                      <td className="px-4 py-2.5">
                        <span className="px-2 py-0.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded text-xs font-medium">
                          {rel.type}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-slate-200 font-mono text-xs">{rel.target}</td>
                      <td className="px-4 py-2.5 text-slate-300 font-mono">{(rel.confidence * 100).toFixed(0)}%</td>
                      <td className="px-4 py-2.5 text-slate-400 text-xs max-w-[300px] truncate">{rel.evidence}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {/* Metadata */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="mt-6 text-xs text-slate-500 flex flex-wrap gap-4"
        >
          <span>Enriched: {new Date(doc.enriched_at).toLocaleString()}</span>
          <span>Version: {doc.enrichment_version}</span>
          <span>Methods: {doc.methods.entity_extraction.join(', ')}</span>
        </motion.div>
      </div>
    </div>
  );
}
