"""
Evaluation utilities for the NLP enrichment pipeline.

Compares predicted labels (from weak supervision) against a gold evaluation set.
Computes precision, recall, and F1 per category and overall. Generates
evaluation reports for sponsor demos and development iteration.
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Set


def _safe_precision(tp: int, fp: int) -> float:
    denom = tp + fp
    return tp / denom if denom > 0 else 0.0


def _safe_recall(tp: int, fn: int) -> float:
    denom = tp + fn
    return tp / denom if denom > 0 else 0.0


def _safe_f1(precision: float, recall: float) -> float:
    denom = precision + recall
    return 2 * precision * recall / denom if denom > 0 else 0.0


def evaluate_labels(predictions: List[Dict], gold_set: List[Dict]) -> Dict:
    """
    Compare predicted labels against gold labels and compute per-category and
    aggregated metrics.

    Args:
        predictions: List of docs with "id" and "predicted_labels" (dict of
            {label: confidence}). Any label present in predicted_labels is
            treated as a positive prediction.
        gold_set: List of docs with "id" and "labels" (list of gold label strings).

    Returns:
        Dict with per_category, micro_avg, macro_avg, total_documents,
        matched_documents, and unmatched_ids.
    """
    gold_by_id: Dict[str, Set[str]] = {}
    for doc in gold_set or []:
        doc_id = doc.get("id")
        if doc_id is None:
            continue
        labels = doc.get("labels")
        if labels is None:
            labels = []
        gold_by_id[str(doc_id)] = set(labels) if isinstance(labels, list) else set()

    pred_by_id: Dict[str, Set[str]] = {}
    for doc in predictions or []:
        doc_id = doc.get("id")
        if doc_id is None:
            continue
        pl = doc.get("predicted_labels")
        if pl is None:
            pl = {}
        pred_by_id[str(doc_id)] = set(pl.keys()) if isinstance(pl, dict) else set()

    all_categories: Set[str] = set()
    for s in gold_by_id.values():
        all_categories.update(s)
    for s in pred_by_id.values():
        all_categories.update(s)

    if not all_categories:
        per_cat = {}
        for c in ["vulnerability", "exploit", "phishing", "ransomware", "threat_actor", "ioc"]:
            per_cat[c] = {"precision": 0.0, "recall": 0.0, "f1": 0.0, "support": 0, "predicted": 0}
        return {
            "per_category": per_cat,
            "micro_avg": {"precision": 0.0, "recall": 0.0, "f1": 0.0},
            "macro_avg": {"precision": 0.0, "recall": 0.0, "f1": 0.0},
            "total_documents": len(gold_by_id),
            "matched_documents": 0,
            "unmatched_ids": sorted(gold_by_id.keys()),
        }

    matched_ids = set(gold_by_id.keys()) & set(pred_by_id.keys())
    unmatched_ids = sorted(set(gold_by_id.keys()) - set(pred_by_id.keys()))
    total_docs = len(gold_by_id)

    per_category: Dict[str, Dict] = {}
    total_tp = total_fp = total_fn = 0

    for cat in sorted(all_categories):
        tp = fp = fn = 0
        for doc_id in matched_ids:
            gold_labels = gold_by_id.get(doc_id, set())
            pred_labels = pred_by_id.get(doc_id, set())
            in_gold = cat in gold_labels
            in_pred = cat in pred_labels
            if in_gold and in_pred:
                tp += 1
            elif in_pred and not in_gold:
                fp += 1
            elif in_gold and not in_pred:
                fn += 1

        support = tp + fn
        predicted = tp + fp
        p = _safe_precision(tp, fp)
        r = _safe_recall(tp, fn)
        f1 = _safe_f1(p, r)

        per_category[cat] = {
            "precision": round(p, 2),
            "recall": round(r, 2),
            "f1": round(f1, 2),
            "support": support,
            "predicted": predicted,
        }
        total_tp += tp
        total_fp += fp
        total_fn += fn

    micro_p = _safe_precision(total_tp, total_fp)
    micro_r = _safe_recall(total_tp, total_fn)
    micro_f1 = _safe_f1(micro_p, micro_r)

    precisions = [v["precision"] for v in per_category.values()]
    recalls = [v["recall"] for v in per_category.values()]
    f1s = [v["f1"] for v in per_category.values()]
    n = len(per_category) or 1
    macro_avg = {
        "precision": round(sum(precisions) / n, 2),
        "recall": round(sum(recalls) / n, 2),
        "f1": round(sum(f1s) / n, 2),
    }

    return {
        "per_category": per_category,
        "micro_avg": {
            "precision": round(micro_p, 2),
            "recall": round(micro_r, 2),
            "f1": round(micro_f1, 2),
        },
        "macro_avg": macro_avg,
        "total_documents": total_docs,
        "matched_documents": len(matched_ids),
        "unmatched_ids": unmatched_ids,
    }


def generate_report(eval_results: Dict, output_path: Optional[str] = None) -> str:
    """
    Produce a formatted text report from evaluation results.

    Args:
        eval_results: Output from evaluate_labels.
        output_path: If provided, write the report to this file.

    Returns:
        The report string.
    """
    lines = [
        "NLP Evaluation Report",
        "=====================",
        f"Date: {datetime.now().strftime('%Y-%m-%d')}",
        f"Documents evaluated: {eval_results.get('total_documents', 0)}",
        f"Documents matched: {eval_results.get('matched_documents', 0)}",
        "",
        "Per-Category Results:",
        "  Category        Precision  Recall    F1       Support  Predicted",
    ]

    category_order = ["vulnerability", "exploit", "phishing", "ransomware", "threat_actor", "ioc"]
    per_cat = eval_results.get("per_category", {})
    ordered_cats = [c for c in category_order if c in per_cat]
    for extra in sorted(per_cat.keys()):
        if extra not in category_order:
            ordered_cats.append(extra)
    for cat in ordered_cats:
        m = per_cat[cat]
        p = m.get("precision", 0)
        r = m.get("recall", 0)
        f1 = m.get("f1", 0)
        sup = m.get("support", 0)
        pred = m.get("predicted", 0)
        lines.append(f"  {cat:<15} {p:<9.2f}  {r:<9.2f}  {f1:<9.2f}  {sup:<7}  {pred}")

    micro = eval_results.get("micro_avg", {})
    macro = eval_results.get("macro_avg", {})
    mp = micro.get("precision", 0)
    mr = micro.get("recall", 0)
    mf = micro.get("f1", 0)
    map_p = macro.get("precision", 0)
    map_r = macro.get("recall", 0)
    map_f = macro.get("f1", 0)

    lines.extend([
        "",
        "Aggregated Metrics:",
        f"  Micro-average:  P={mp:.2f}  R={mr:.2f}  F1={mf:.2f}",
        f"  Macro-average:  P={map_p:.2f}  R={map_r:.2f}  F1={map_f:.2f}",
        "",
    ])

    verdict = "PASS" if map_f >= 0.70 else "FAIL"
    lines.append(f"Verdict: {verdict} (macro F1 >= 0.70)")

    report = "\n".join(lines)

    if output_path:
        with open(output_path, "w") as f:
            f.write(report)

    return report


def load_gold_set(gold_path: str) -> List[Dict]:
    """
    Load gold set from a JSONL file.

    Each line must be a JSON object with at least "id" and "labels" keys.
    labels should be a list of strings (e.g. ["vulnerability", "exploit"]).

    Args:
        gold_path: Path to the JSONL file.

    Returns:
        List of dicts, one per line.
    """
    result: List[Dict] = []
    with open(gold_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict) and "id" in obj:
                    result.append(obj)
            except json.JSONDecodeError:
                continue
    return result


def run_evaluation(
    predictions: List[Dict],
    gold_path: str,
    report_path: Optional[str] = None,
) -> Dict:
    """
    Load gold set, run evaluate_labels, generate report, and return results.

    Args:
        predictions: List of docs with "id" and "predicted_labels".
        gold_path: Path to gold set JSONL file.
        report_path: If provided, write the evaluation report to this path.

    Returns:
        The evaluation result dict from evaluate_labels.
    """
    gold_set = load_gold_set(gold_path)
    eval_results = evaluate_labels(predictions, gold_set)
    generate_report(eval_results, output_path=report_path)
    return eval_results
