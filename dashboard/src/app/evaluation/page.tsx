'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Loader2, FlaskConical, CheckCircle2, XCircle } from 'lucide-react';
import { Stats, EvalMetric } from '@/lib/types';

function f1Color(f1: number): string {
  if (f1 >= 0.9) return 'text-green-400';
  if (f1 >= 0.7) return 'text-yellow-400';
  return 'text-red-400';
}

function f1BgColor(f1: number): string {
  if (f1 >= 0.9) return 'bg-green-500/10';
  if (f1 >= 0.7) return 'bg-yellow-500/10';
  return 'bg-red-500/10';
}

function PassFailBadge({ f1, threshold = 0.7 }: { f1: number; threshold?: number }) {
  const pass = f1 >= threshold;
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-bold ${
        pass
          ? 'bg-green-500/20 text-green-400 border border-green-500/30'
          : 'bg-red-500/20 text-red-400 border border-red-500/30'
      }`}
    >
      {pass ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
      {pass ? 'PASS' : 'FAIL'}
    </span>
  );
}

function MetricTable({
  title,
  metrics,
  macroF1,
  delay,
}: {
  title: string;
  metrics: EvalMetric[];
  macroF1: number;
  delay: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden"
    >
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
        <h2 className="text-lg font-semibold text-slate-200">{title}</h2>
        <div className="flex items-center gap-3">
          <span className="text-sm text-slate-400">
            Macro F1:{' '}
            <span className={`font-mono font-bold ${f1Color(macroF1)}`}>
              {macroF1.toFixed(2)}
            </span>
          </span>
          <PassFailBadge f1={macroF1} />
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700 bg-slate-800/50">
              <th className="text-left px-6 py-3 text-slate-400 font-medium">Category</th>
              <th className="text-right px-6 py-3 text-slate-400 font-medium">Precision</th>
              <th className="text-right px-6 py-3 text-slate-400 font-medium">Recall</th>
              <th className="text-right px-6 py-3 text-slate-400 font-medium">F1 Score</th>
              <th className="text-right px-6 py-3 text-slate-400 font-medium">Support</th>
            </tr>
          </thead>
          <tbody>
            {metrics.map((m, i) => (
              <tr
                key={m.name}
                className={i % 2 === 0 ? 'bg-slate-800/30' : 'bg-slate-800/60'}
              >
                <td className="px-6 py-3 border-b border-slate-700/30">
                  <span className="text-slate-200 font-medium">{m.name}</span>
                </td>
                <td className="px-6 py-3 border-b border-slate-700/30 text-right font-mono text-slate-300">
                  {m.precision.toFixed(2)}
                </td>
                <td className="px-6 py-3 border-b border-slate-700/30 text-right font-mono text-slate-300">
                  {m.recall.toFixed(2)}
                </td>
                <td className={`px-6 py-3 border-b border-slate-700/30 text-right font-mono font-bold ${f1Color(m.f1)} ${f1BgColor(m.f1)}`}>
                  {m.f1.toFixed(2)}
                </td>
                <td className="px-6 py-3 border-b border-slate-700/30 text-right font-mono text-slate-400">
                  {m.support.toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </motion.div>
  );
}

export default function EvaluationPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/data/stats.json')
      .then((r) => r.json())
      .then((data: Stats) => {
        setStats(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  if (loading || !stats) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
        <span className="ml-3 text-slate-300 text-lg">Loading evaluation data...</span>
      </div>
    );
  }

  const { evaluation } = stats;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="max-w-[1200px] mx-auto px-6 py-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-3xl font-bold text-slate-100 flex items-center gap-3">
            <FlaskConical className="w-8 h-8 text-cyan-400" />
            Model Performance
          </h1>
          <p className="text-slate-400 mt-1">
            Evaluation metrics for classification and NER models
          </p>
        </motion.div>

        {/* Summary Cards */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8"
        >
          <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400 mb-1">Classification Macro F1</p>
                <p className={`text-4xl font-bold font-mono ${f1Color(evaluation.classification_macro_f1)}`}>
                  {evaluation.classification_macro_f1.toFixed(2)}
                </p>
              </div>
              <PassFailBadge f1={evaluation.classification_macro_f1} />
            </div>
            <div className="mt-4 w-full h-2 bg-slate-900 rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${evaluation.classification_macro_f1 * 100}%` }}
                transition={{ duration: 0.8, ease: 'easeOut' }}
                className={`h-full rounded-full ${
                  evaluation.classification_macro_f1 >= 0.9
                    ? 'bg-green-500'
                    : evaluation.classification_macro_f1 >= 0.7
                    ? 'bg-yellow-500'
                    : 'bg-red-500'
                }`}
              />
            </div>
          </div>

          <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400 mb-1">NER Macro F1</p>
                <p className={`text-4xl font-bold font-mono ${f1Color(evaluation.ner_macro_f1)}`}>
                  {evaluation.ner_macro_f1.toFixed(2)}
                </p>
              </div>
              <PassFailBadge f1={evaluation.ner_macro_f1} />
            </div>
            <div className="mt-4 w-full h-2 bg-slate-900 rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${evaluation.ner_macro_f1 * 100}%` }}
                transition={{ duration: 0.8, ease: 'easeOut' }}
                className={`h-full rounded-full ${
                  evaluation.ner_macro_f1 >= 0.9
                    ? 'bg-green-500'
                    : evaluation.ner_macro_f1 >= 0.7
                    ? 'bg-yellow-500'
                    : 'bg-red-500'
                }`}
              />
            </div>
          </div>
        </motion.div>

        {/* Classification Table */}
        <div className="space-y-8">
          <MetricTable
            title="Classification Performance"
            metrics={evaluation.classification_per_category}
            macroF1={evaluation.classification_macro_f1}
            delay={0.1}
          />

          <MetricTable
            title="NER Performance"
            metrics={evaluation.ner_per_type}
            macroF1={evaluation.ner_macro_f1}
            delay={0.15}
          />
        </div>
      </div>
    </div>
  );
}
