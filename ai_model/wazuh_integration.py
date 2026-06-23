"""
SOC False Alarm Reduction - Wazuh Integration Script
Monitors Wazuh alerts in real-time, classifies them using the trained AI model,
and outputs filtered results (suppressing false positives).

This script acts as the Human-AI Collaboration layer:
- AI automatically classifies incoming alerts
- True positives are escalated for human review
- False positives are logged but suppressed from the main feed
- Human analysts can override AI decisions

Usage:
    python wazuh_integration.py                  # Run in real-time monitoring mode
    python wazuh_integration.py --batch          # Process existing alerts file
    python wazuh_integration.py --api            # Run as Flask API endpoint
"""

import json
import os
import sys
import time
import argparse
from datetime import datetime

import joblib
import numpy as np

# ── Paths ──────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
MODEL_FILE = os.path.join(SCRIPT_DIR, "soc_rf_model.pkl")
ENCODERS_FILE = os.path.join(SCRIPT_DIR, "label_encoders.pkl")
FEATURES_FILE = os.path.join(SCRIPT_DIR, "feature_config.json")
ALERTS_FILE = os.path.join(PROJECT_DIR, "alerts_raw.json")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
TP_LOG = os.path.join(OUTPUT_DIR, "true_positives.json")
FP_LOG = os.path.join(OUTPUT_DIR, "false_positives.json")
SUMMARY_LOG = os.path.join(OUTPUT_DIR, "classification_summary.json")

# ── Attack definitions ─────────────────────────────────────────────
ATTACK_RULES = {
    "100001", "100010", "100011", "100012", "100013",
    "100020", "100021", "100022", "100023",
}
ATTACK_GROUPS = {"attack", "malware", "phishing", "social_engineering"}


# ── Feature extraction (same as training) ──────────────────────────
def extract_features(alert: dict) -> dict:
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    syscheck = alert.get("syscheck", {})
    decoder = alert.get("decoder", {})
    groups = rule.get("groups", [])
    mitre = rule.get("mitre", {})
    full_log = alert.get("full_log", "")
    location = alert.get("location", "")

    return {
        "rule_id": str(rule.get("id", "0")),
        "rule_level": int(rule.get("level", 0)),
        "firedtimes": int(rule.get("firedtimes", 0)),
        "has_attack_group": int(any(g in ATTACK_GROUPS for g in groups)),
        "has_sca_group": int("sca" in groups),
        "has_syscheck_group": int("syscheck" in groups),
        "has_web_group": int("web" in groups or "nginx" in groups),
        "has_ossec_group": int("ossec" in groups),
        "num_groups": len(groups),
        "has_mitre": int(bool(mitre.get("id", []))),
        "num_mitre_techniques": len(mitre.get("id", [])),
        "is_manager_alert": int(agent.get("id", "000") == "000"),
        "decoder_name": decoder.get("name", "unknown"),
        "is_sca_decoder": int(decoder.get("name", "") == "sca"),
        "is_syscheck_decoder": int("syscheck" in decoder.get("name", "")),
        "has_syscheck_data": int(bool(syscheck)),
        "is_file_added": int(syscheck.get("event", "") == "added"),
        "is_file_modified": int(syscheck.get("event", "") == "modified"),
        "is_syscheck_location": int(location == "syscheck"),
        "is_log_location": int("/var/log" in location),
        "log_length": len(full_log),
        "has_suspicious_keywords": int(any(
            kw in full_log.lower() for kw in [
                "backdoor", "shell", "exploit", "payload", "reverse",
                "malware", "trojan", "curl http", "wget http",
                "phishing", "credential", "fake-login",
            ]
        )),
        "has_tmp_path": int("/tmp/" in full_log),
        "has_web_path": int("/usr/share/nginx" in full_log or "/var/www" in full_log),
    }


class SOCAlertClassifier:
    """AI-powered SOC alert classifier for false alarm reduction."""

    def __init__(self):
        print("[*] Loading AI model...")
        self.model = joblib.load(MODEL_FILE)
        self.encoders = joblib.load(ENCODERS_FILE)
        with open(FEATURES_FILE) as f:
            self.config = json.load(f)
        self.feature_cols = self.config["feature_columns"]
        print("[*] Model loaded successfully")

        # Stats
        self.stats = {
            "total_processed": 0,
            "true_positives": 0,
            "false_positives": 0,
            "start_time": datetime.now().isoformat(),
        }

    def classify(self, alert: dict) -> dict:
        """Classify a single alert. Returns classification result."""
        features = extract_features(alert)

        # Encode categorical features
        rule_id = features["rule_id"]
        decoder_name = features["decoder_name"]

        try:
            rule_id_enc = self.encoders["rule_id"].transform([rule_id])[0]
        except ValueError:
            rule_id_enc = -1  # Unknown rule

        try:
            decoder_enc = self.encoders["decoder_name"].transform([decoder_name])[0]
        except ValueError:
            decoder_enc = -1  # Unknown decoder

        # Build feature vector
        feature_vector = [
            features["rule_level"],
            features["firedtimes"],
            features["has_attack_group"],
            features["has_sca_group"],
            features["has_syscheck_group"],
            features["has_web_group"],
            features["has_ossec_group"],
            features["num_groups"],
            features["has_mitre"],
            features["num_mitre_techniques"],
            features["is_manager_alert"],
            features["is_sca_decoder"],
            features["is_syscheck_decoder"],
            features["has_syscheck_data"],
            features["is_file_added"],
            features["is_file_modified"],
            features["is_syscheck_location"],
            features["is_log_location"],
            features["log_length"],
            features["has_suspicious_keywords"],
            features["has_tmp_path"],
            features["has_web_path"],
            rule_id_enc,
            decoder_enc,
        ]

        X = np.array([feature_vector])
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        confidence = max(probabilities)

        classification = "TRUE_POSITIVE" if prediction == 1 else "FALSE_POSITIVE"

        result = {
            "timestamp": alert.get("timestamp", datetime.now().isoformat()),
            "rule_id": rule_id,
            "rule_level": features["rule_level"],
            "rule_description": alert.get("rule", {}).get("description", ""),
            "agent": alert.get("agent", {}).get("name", "unknown"),
            "classification": classification,
            "confidence": round(float(confidence), 4),
            "action": "ESCALATE" if classification == "TRUE_POSITIVE" else "SUPPRESS",
            "mitre": alert.get("rule", {}).get("mitre", {}),
        }

        self.stats["total_processed"] += 1
        if classification == "TRUE_POSITIVE":
            self.stats["true_positives"] += 1
        else:
            self.stats["false_positives"] += 1

        return result

    def get_summary(self) -> dict:
        """Get classification summary statistics."""
        total = self.stats["total_processed"]
        fp = self.stats["false_positives"]
        tp = self.stats["true_positives"]
        return {
            **self.stats,
            "end_time": datetime.now().isoformat(),
            "false_alarm_reduction_rate": f"{(fp / total * 100):.1f}%" if total > 0 else "N/A",
            "true_positive_rate": f"{(tp / total * 100):.1f}%" if total > 0 else "N/A",
            "alerts_requiring_human_review": tp,
            "alerts_auto_suppressed": fp,
        }


def run_batch_mode(classifier: SOCAlertClassifier):
    """Process existing alerts file in batch mode."""
    print(f"\n[BATCH MODE] Processing {ALERTS_FILE}")
    print("-" * 70)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    tp_alerts = []
    fp_alerts = []

    with open(ALERTS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            result = classifier.classify(alert)

            # Color-coded console output
            if result["classification"] == "TRUE_POSITIVE":
                icon = "\033[91m[!] ATTACK\033[0m"
                tp_alerts.append({**result, "full_alert": alert})
            else:
                icon = "\033[92m[~] BENIGN\033[0m"
                fp_alerts.append({**result, "full_alert": alert})

            print(f"  {icon}  Rule {result['rule_id']:>6} (L{result['rule_level']:>2}) "
                  f"| {result['confidence']:.2f} conf | {result['rule_description'][:50]}")

    # Save results
    with open(TP_LOG, "w") as f:
        json.dump(tp_alerts, f, indent=2)
    with open(FP_LOG, "w") as f:
        json.dump(fp_alerts, f, indent=2)

    summary = classifier.get_summary()
    with open(SUMMARY_LOG, "w") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 70)
    print("CLASSIFICATION SUMMARY")
    print("=" * 70)
    print(f"  Total alerts processed:        {summary['total_processed']}")
    print(f"  True Positives (ESCALATE):     {summary['true_positives']}")
    print(f"  False Positives (SUPPRESS):    {summary['false_positives']}")
    print(f"  False Alarm Reduction Rate:    {summary['false_alarm_reduction_rate']}")
    print(f"  Alerts for Human Review:       {summary['alerts_requiring_human_review']}")
    print(f"\n  Output files:")
    print(f"    {TP_LOG}")
    print(f"    {FP_LOG}")
    print(f"    {SUMMARY_LOG}")


def run_realtime_mode(classifier: SOCAlertClassifier):
    """Monitor alerts file for new entries (tail -f style)."""
    print(f"\n[REAL-TIME MODE] Monitoring {ALERTS_FILE}")
    print("Press Ctrl+C to stop\n")
    print("-" * 70)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Start from end of file
    with open(ALERTS_FILE) as f:
        f.seek(0, 2)  # Seek to end
        while True:
            try:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue

                line = line.strip()
                if not line:
                    continue

                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue

                result = classifier.classify(alert)

                if result["classification"] == "TRUE_POSITIVE":
                    icon = "\033[91m[!] ATTACK\033[0m"
                    with open(TP_LOG, "a") as tp_f:
                        tp_f.write(json.dumps(result) + "\n")
                else:
                    icon = "\033[92m[~] BENIGN\033[0m"
                    with open(FP_LOG, "a") as fp_f:
                        fp_f.write(json.dumps(result) + "\n")

                now = datetime.now().strftime("%H:%M:%S")
                print(f"  [{now}] {icon}  Rule {result['rule_id']:>6} "
                      f"| {result['confidence']:.2f} | {result['action']:>8} "
                      f"| {result['rule_description'][:45]}")

            except KeyboardInterrupt:
                print("\n\nStopping...")
                summary = classifier.get_summary()
                print(f"\nSession summary:")
                print(f"  Processed: {summary['total_processed']}")
                print(f"  Escalated: {summary['true_positives']}")
                print(f"  Suppressed: {summary['false_positives']}")
                break


def main():
    parser = argparse.ArgumentParser(description="SOC Alert AI Classifier")
    parser.add_argument("--batch", action="store_true", help="Process alerts in batch mode")
    parser.add_argument("--realtime", action="store_true", help="Monitor alerts in real-time")
    args = parser.parse_args()

    classifier = SOCAlertClassifier()

    if args.batch:
        run_batch_mode(classifier)
    elif args.realtime:
        run_realtime_mode(classifier)
    else:
        # Default: batch mode
        run_batch_mode(classifier)


if __name__ == "__main__":
    main()
