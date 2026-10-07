"""
metrics.py - Detection quality measurement.

A detection that has never been measured is a guess. This harness scores the
ruleset against the labelled ground truth produced by the generator and
reports precision, recall and F1 per scenario.

  precision = of the alerts we raised, how many were real?   (noise)
  recall    = of the real attacks, how many did we catch?    (blind spots)

Both matter and they trade off. A rule that alerts on everything has perfect
recall and useless precision; the analyst stops reading. The threshold sweep
makes that tradeoff explicit instead of leaving it to taste.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .pipeline import Pipeline

STANDARD_INPUTS = {
    "auth.log": "auth", "access.log": "nginx", "windows_security.json": "winlog",
    "suricata_eve.json": "suricata", "cowrie.json": "cowrie",
}


def _inputs(input_dir: str) -> dict[str, str]:
    d = Path(input_dir)
    return {str(d / name): src for name, src in STANDARD_INPUTS.items() if (d / name).exists()}


def score(result, truth: list[dict]) -> dict:
    """
    Alert-level scoring against labelled attack entities.

    An alert is a TRUE POSITIVE if its entity appears in ground truth.
    A ground-truth behaviour is DETECTED if any of its expected rules fired
    for that entity.
    """
    attack_entities = {t["entity"] for t in truth}
    tp = [a for a in result.alerts if a.entity in attack_entities]
    fp = [a for a in result.alerts if a.entity not in attack_entities]

    fired: dict[str, set] = defaultdict(set)
    for a in result.alerts:
        fired[a.entity].add(a.rule_id)

    detected, missed = [], []
    for t in truth:
        if fired[t["entity"]] & set(t["expected_rules"]):
            detected.append(t)
        else:
            missed.append(t)

    precision = len(tp) / len(result.alerts) if result.alerts else 0.0
    recall = len(detected) / len(truth) if truth else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    by_scenario: dict[str, dict] = defaultdict(lambda: {"total": 0, "detected": 0})
    for t in truth:
        by_scenario[t["scenario"]]["total"] += 1
    for t in detected:
        by_scenario[t["scenario"]]["detected"] += 1

    return {
        "alerts_total": len(result.alerts),
        "true_positives": len(tp),
        "false_positives": len(fp),
        "false_positive_alerts": [{"entity": a.entity, "rule": a.rule_id,
                                   "severity": a.severity} for a in fp],
        "behaviours_total": len(truth),
        "behaviours_detected": len(detected),
        "missed": [{"scenario": m["scenario"], "technique": m["technique"],
                    "description": m["description"],
                    "expected_rules": m["expected_rules"]} for m in missed],
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "by_scenario": {k: {**v, "recall": round(v["detected"] / v["total"], 3)}
                        for k, v in sorted(by_scenario.items())},
        "techniques_detected": sorted({t["technique"] for t in detected}),
    }


def threshold_sweep(input_dir: str, rules_dir: str, config_dir: str, year: int,
                    values=(3, 5, 8, 10, 15, 20, 30)) -> list[dict]:
    """
    Re-run the pipeline at different brute-force thresholds.

    This table is the single most SOC-relevant artifact in the repo: it shows
    the tuning decision was measured, not guessed.
    """
    import yaml
    rule_path = Path(rules_dir) / "atomic" / "001_ssh_brute_force.yml"
    original = rule_path.read_text(encoding="utf-8")
    data = yaml.safe_load(original)
    truth = json.loads((Path(input_dir) / "ground_truth.json").read_text(encoding="utf-8"))
    rows = []
    try:
        for value in values:
            data["detection"]["threshold"]["count"] = value
            rule_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
            result = Pipeline(rules_dir, config_dir).run(_inputs(input_dir), year=year)
            bf = [a for a in result.alerts if a.rule_id == "ssh_brute_force"]
            attack_entities = {t["entity"] for t in truth}
            tp = len([a for a in bf if a.entity in attack_entities])
            fp = len(bf) - tp
            rows.append({"threshold": value, "alerts": len(bf), "true_positives": tp,
                         "false_positives": fp,
                         "precision": round(tp / len(bf), 3) if bf else 0.0})
    finally:
        rule_path.write_text(original, encoding="utf-8")   # always restore the rule file
    return rows


def evaluate(input_dir: str = "sample_logs", rules_dir: str = "rules",
             config_dir: str = "config", year: int = 2026, sweep: bool = False) -> int:
    truth_path = Path(input_dir) / "ground_truth.json"
    if not truth_path.exists():
        print(f"No ground_truth.json in {input_dir}. Run tools/generate_logs.py first.")
        return 1
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    result = Pipeline(rules_dir, config_dir).run(_inputs(input_dir), year=year)
    m = score(result, truth)

    bar = "─" * 66
    print(f"\n{bar}\n  DETECTION QUALITY METRICS\n{bar}")
    print(f"  Events analysed        {len(result.events)}")
    print(f"  Alerts raised          {m['alerts_total']}")
    print(f"  True positives         {m['true_positives']}")
    print(f"  False positives        {m['false_positives']}")
    print(f"  Attack behaviours      {m['behaviours_detected']}/{m['behaviours_total']} detected")
    print(f"\n  PRECISION              {m['precision']:.1%}   (alerts that were real)")
    print(f"  RECALL                 {m['recall']:.1%}   (attacks we caught)")
    print(f"  F1 SCORE               {m['f1']:.3f}")

    print(f"\n  {'SCENARIO':<10}{'DETECTED':>10}{'TOTAL':>8}{'RECALL':>9}")
    for name, v in m["by_scenario"].items():
        print(f"  {name:<10}{v['detected']:>10}{v['total']:>8}{v['recall']:>9.0%}")

    if m["false_positive_alerts"]:
        print("\n  FALSE POSITIVES")
        for fp in m["false_positive_alerts"]:
            print(f"    {fp['severity']:<9}{fp['rule']:<32}{fp['entity']}")
    if m["missed"]:
        print("\n  MISSED BEHAVIOURS")
        for miss in m["missed"]:
            print(f"    [{miss['scenario']}] {miss['technique']:<12}{miss['description']}")
            print(f"              expected: {', '.join(miss['expected_rules'])}")

    print(f"\n  ATT&CK techniques detected: {', '.join(m['techniques_detected'])}")

    if sweep:
        print(f"\n{bar}\n  THRESHOLD SWEEP: ssh_brute_force count\n{bar}")
        print(f"  {'THRESHOLD':<12}{'ALERTS':>8}{'TP':>6}{'FP':>6}{'PRECISION':>12}")
        for row in threshold_sweep(input_dir, rules_dir, config_dir, year):
            print(f"  {row['threshold']:<12}{row['alerts']:>8}{row['true_positives']:>6}"
                  f"{row['false_positives']:>6}{row['precision']:>11.0%}")
        print("\n  Lower thresholds catch slower attacks but surface benign retry\n"
              "  behaviour (expired service accounts, misconfigured clients).")

    out = Path("out"); out.mkdir(exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    print(f"\n  Written to out/metrics.json\n{bar}\n")
    # Non-zero exit if quality regresses - this is what gates CI
    return 0 if (m["recall"] >= 0.8 and m["precision"] >= 0.8) else 2
