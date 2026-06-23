"""
SOC False Alarm Reduction - AI Model Training Pipeline
Reduces false positives in Wazuh SIEM alerts using Random Forest classifier.

Steps:
1. Parse raw Wazuh alerts JSON
2. Extract features (rule level, groups, decoder, agent, etc.)
3. Label alerts (attack rules = true_positive, noise = false_positive)
4. Augment dataset with synthetic variations for robustness
5. Train Random Forest classifier
6. Evaluate with precision, recall, F1, confusion matrix
7. Save model + feature config for integration
"""

import json
import os
import random
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.preprocessing import LabelEncoder
import joblib

# ── Paths ──────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
ALERTS_FILE = os.path.join(PROJECT_DIR, "alerts_raw.json")
MODEL_DIR = SCRIPT_DIR
MODEL_FILE = os.path.join(MODEL_DIR, "soc_rf_model.pkl")
ENCODERS_FILE = os.path.join(MODEL_DIR, "label_encoders.pkl")
FEATURES_FILE = os.path.join(MODEL_DIR, "feature_config.json")
DATASET_FILE = os.path.join(MODEL_DIR, "dataset.csv")
RESULTS_FILE = os.path.join(MODEL_DIR, "evaluation_results.txt")

# ── Attack rule IDs (true positives) ──────────────────────────────
ATTACK_RULES = {
    "100001",  # DDoS
    "100010",  # Malware - /tmp
    "100011",  # Malware - webshell
    "100012",  # Malware - suspicious filename
    "100013",  # Malware - permission change
    "100020",  # Phishing email
    "100021",  # Phishing URL
    "100022",  # Phishing C2 callback
    "100023",  # Phishing payload download
}

# All known attack group tags
ATTACK_GROUPS = {"attack", "malware", "phishing", "social_engineering"}

# ── Feature extraction ────────────────────────────────────────────
def extract_features(alert: dict) -> dict:
    """Extract ML features from a single Wazuh alert JSON."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    syscheck = alert.get("syscheck", {})
    decoder = alert.get("decoder", {})
    groups = rule.get("groups", [])

    # Basic rule features
    rule_id = str(rule.get("id", "0"))
    rule_level = int(rule.get("level", 0))
    firedtimes = int(rule.get("firedtimes", 0))

    # Group-based features
    has_attack_group = int(any(g in ATTACK_GROUPS for g in groups))
    has_sca_group = int("sca" in groups)
    has_syscheck_group = int("syscheck" in groups)
    has_web_group = int("web" in groups or "nginx" in groups)
    has_ossec_group = int("ossec" in groups)
    num_groups = len(groups)

    # MITRE features
    mitre = rule.get("mitre", {})
    has_mitre = int(bool(mitre.get("id", [])))
    num_mitre_techniques = len(mitre.get("id", []))

    # Agent features
    agent_id = agent.get("id", "000")
    is_manager_alert = int(agent_id == "000")

    # Decoder features
    decoder_name = decoder.get("name", "unknown")
    is_sca_decoder = int(decoder_name == "sca")
    is_syscheck_decoder = int("syscheck" in decoder_name)

    # Syscheck features (file integrity)
    has_syscheck_data = int(bool(syscheck))
    syscheck_event = syscheck.get("event", "none")
    is_file_added = int(syscheck_event == "added")
    is_file_modified = int(syscheck_event == "modified")

    # Location feature
    location = alert.get("location", "")
    is_syscheck_location = int(location == "syscheck")
    is_log_location = int("/var/log" in location)

    # Full log analysis
    full_log = alert.get("full_log", "")
    log_length = len(full_log)
    has_suspicious_keywords = int(
        any(
            kw in full_log.lower()
            for kw in [
                "backdoor", "shell", "exploit", "payload", "reverse",
                "malware", "trojan", "curl http", "wget http",
                "phishing", "credential", "fake-login",
            ]
        )
    )
    has_tmp_path = int("/tmp/" in full_log)
    has_web_path = int("/usr/share/nginx" in full_log or "/var/www" in full_log)

    return {
        "rule_id": rule_id,
        "rule_level": rule_level,
        "firedtimes": firedtimes,
        "has_attack_group": has_attack_group,
        "has_sca_group": has_sca_group,
        "has_syscheck_group": has_syscheck_group,
        "has_web_group": has_web_group,
        "has_ossec_group": has_ossec_group,
        "num_groups": num_groups,
        "has_mitre": has_mitre,
        "num_mitre_techniques": num_mitre_techniques,
        "is_manager_alert": is_manager_alert,
        "decoder_name": decoder_name,
        "is_sca_decoder": is_sca_decoder,
        "is_syscheck_decoder": is_syscheck_decoder,
        "has_syscheck_data": has_syscheck_data,
        "is_file_added": is_file_added,
        "is_file_modified": is_file_modified,
        "is_syscheck_location": is_syscheck_location,
        "is_log_location": is_log_location,
        "log_length": log_length,
        "has_suspicious_keywords": has_suspicious_keywords,
        "has_tmp_path": has_tmp_path,
        "has_web_path": has_web_path,
    }


def label_alert(alert: dict) -> str:
    """Label alert as true_positive (real attack) or false_positive (noise)."""
    rule_id = str(alert.get("rule", {}).get("id", "0"))
    if rule_id in ATTACK_RULES:
        return "true_positive"
    return "false_positive"


# ── Synthetic data augmentation ───────────────────────────────────
def generate_synthetic_alerts(real_alerts: list, num_synthetic: int = 300) -> list:
    """Generate synthetic alert variations to augment training data."""
    synthetic = []
    random.seed(42)

    # Separate by label
    tp_alerts = [a for a in real_alerts if label_alert(a) == "true_positive"]
    fp_alerts = [a for a in real_alerts if label_alert(a) == "false_positive"]

    # Generate synthetic true positives (attack variations)
    attack_templates = [
        {
            "rule": {"id": "100001", "level": 12, "description": "DDoS detected",
                     "firedtimes": 1, "groups": ["web", "nginx", "attack"],
                     "mitre": {"id": ["T1498"], "tactic": ["Impact"], "technique": ["Network Denial of Service"]}},
            "agent": {"id": "001", "name": "agent", "ip": "8.8.8.3"},
            "decoder": {"name": "nginx_access"}, "location": "/var/log/nginx/access.log",
            "full_log": "GET / HTTP/1.1 200 615 curl/8.19.0",
        },
        {
            "rule": {"id": "100012", "level": 14, "description": "Malware - File with suspicious name created",
                     "firedtimes": 1, "groups": ["malware", "syscheck", "attack"],
                     "mitre": {"id": ["T1204"], "tactic": ["Execution"], "technique": ["User Execution"]}},
            "agent": {"id": "001", "name": "agent", "ip": "8.8.8.3"},
            "decoder": {"name": "syscheck_new_entry"}, "location": "syscheck",
            "syscheck": {"path": "/tmp/malware.sh", "event": "added"},
            "full_log": "File '/tmp/backdoor.sh' added",
        },
        {
            "rule": {"id": "100011", "level": 13, "description": "Malware - Suspicious file in web directory",
                     "firedtimes": 1, "groups": ["malware", "syscheck", "attack"],
                     "mitre": {"id": ["T1505.003"], "tactic": ["Persistence"], "technique": ["Server Software Component"]}},
            "agent": {"id": "001", "name": "agent", "ip": "8.8.8.3"},
            "decoder": {"name": "syscheck_new_entry"}, "location": "syscheck",
            "syscheck": {"path": "/usr/share/nginx/html/shell.php", "event": "added"},
            "full_log": "File '/usr/share/nginx/html/shell.php' added",
        },
        {
            "rule": {"id": "100022", "level": 13, "description": "Social Engineering - Suspicious outbound connection",
                     "firedtimes": 1, "groups": ["social_engineering", "phishing", "attack"],
                     "mitre": {"id": ["T1071"], "tactic": ["Command and Control"], "technique": ["Application Layer Protocol"]}},
            "agent": {"id": "001", "name": "agent", "ip": "8.8.8.3"},
            "decoder": {}, "location": "/var/log/messages",
            "full_log": "curl http://10.20.30.40/payload executed by user after phishing",
        },
        {
            "rule": {"id": "100010", "level": 12, "description": "Malware - Suspicious file created in /tmp",
                     "firedtimes": 1, "groups": ["malware", "syscheck", "attack"],
                     "mitre": {"id": ["T1059"], "tactic": ["Execution"], "technique": ["Command and Scripting Interpreter"]}},
            "agent": {"id": "001", "name": "agent", "ip": "8.8.8.3"},
            "decoder": {"name": "syscheck_new_entry"}, "location": "syscheck",
            "syscheck": {"path": "/tmp/exploit.bin", "event": "added"},
            "full_log": "File '/tmp/exploit.bin' added",
        },
    ]

    # Synthetic false positives (benign noise variations)
    fp_templates = [
        {
            "rule": {"id": "19009", "level": 3, "description": "CIS Benchmark check",
                     "firedtimes": 1, "groups": ["sca"], "mitre": {}},
            "agent": {"id": "000", "name": "wazuh.manager"},
            "decoder": {"name": "sca"}, "location": "sca",
            "full_log": "",
        },
        {
            "rule": {"id": "19007", "level": 7, "description": "CIS Benchmark failed check",
                     "firedtimes": 1, "groups": ["sca"], "mitre": {}},
            "agent": {"id": "000", "name": "wazuh.manager"},
            "decoder": {"name": "sca"}, "location": "sca",
            "full_log": "",
        },
        {
            "rule": {"id": "502", "level": 3, "description": "Wazuh server started",
                     "firedtimes": 1, "groups": ["ossec"], "mitre": {}},
            "agent": {"id": "000", "name": "wazuh.manager"},
            "decoder": {"name": "wazuh"}, "location": "wazuh-monitord",
            "full_log": "ossec: Manager started",
        },
        {
            "rule": {"id": "550", "level": 7, "description": "Integrity checksum changed",
                     "firedtimes": 1, "groups": ["syscheck", "ossec"], "mitre": {}},
            "agent": {"id": "001", "name": "agent", "ip": "8.8.8.3"},
            "decoder": {"name": "syscheck_integrity_changed"}, "location": "syscheck",
            "syscheck": {"path": "/etc/resolv.conf", "event": "modified"},
            "full_log": "File '/etc/resolv.conf' modified",
        },
        {
            "rule": {"id": "554", "level": 5, "description": "File added to system",
                     "firedtimes": 1, "groups": ["syscheck", "ossec"], "mitre": {}},
            "agent": {"id": "001", "name": "agent", "ip": "8.8.8.3"},
            "decoder": {"name": "syscheck_new_entry"}, "location": "syscheck",
            "syscheck": {"path": "/etc/cron.d/newjob", "event": "added"},
            "full_log": "File '/etc/cron.d/newjob' added",
        },
        {
            "rule": {"id": "200", "level": 3, "description": "Web access log entry",
                     "firedtimes": 1, "groups": ["web", "nginx"], "mitre": {}},
            "agent": {"id": "001", "name": "agent", "ip": "8.8.8.3"},
            "decoder": {"name": "nginx_access"}, "location": "/var/log/nginx/access.log",
            "full_log": "192.168.1.1 - - GET /index.html HTTP/1.1 200 612",
        },
    ]

    # Filenames for variation
    malware_files = [
        "backdoor.sh", "reverse.py", "shell.php", "exploit.elf", "payload.bin",
        "trojan.sh", "c99.php", "r57.php", "cmd.php", "meterpreter.exe",
        "rootkit.ko", "keylogger.py", "ransomware.sh", "cryptominer.bin",
    ]
    benign_files = [
        "/etc/resolv.conf", "/etc/hosts", "/etc/hostname", "/etc/crontab",
        "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/fstab",
        "/usr/bin/python3", "/usr/sbin/sshd",
    ]
    c2_ips = [
        "10.20.30.40", "192.168.99.1", "172.16.0.50", "10.0.0.100",
        "203.0.113.5", "198.51.100.10", "45.33.32.156", "185.220.101.1",
    ]

    # Generate TP variations
    tp_count = num_synthetic // 2
    for i in range(tp_count):
        template = random.choice(attack_templates).copy()
        template["rule"] = template["rule"].copy()
        template["rule"]["firedtimes"] = random.randint(1, 50)

        rid = template["rule"]["id"]
        if rid in ("100012", "100010"):
            fname = random.choice(malware_files)
            path = f"/tmp/{fname}"
            template["full_log"] = f"File '{path}' added"
            template["syscheck"] = {"path": path, "event": "added"}
        elif rid == "100011":
            fname = random.choice(malware_files)
            path = f"/usr/share/nginx/html/{fname}"
            template["full_log"] = f"File '{path}' added"
            template["syscheck"] = {"path": path, "event": "added"}
        elif rid == "100022":
            ip = random.choice(c2_ips)
            template["full_log"] = f"curl http://{ip}/payload download malware"
        elif rid == "100001":
            template["rule"]["firedtimes"] = random.randint(50, 500)

        synthetic.append(template)

    # Generate FP variations
    fp_count = num_synthetic - tp_count
    for i in range(fp_count):
        template = random.choice(fp_templates).copy()
        template["rule"] = template["rule"].copy()
        template["rule"]["firedtimes"] = random.randint(1, 100)

        rid = template["rule"]["id"]
        if rid in ("550", "554"):
            path = random.choice(benign_files)
            event = random.choice(["added", "modified"])
            template["full_log"] = f"File '{path}' {event}"
            template["syscheck"] = {"path": path, "event": event}

        synthetic.append(template)

    return synthetic


# ── Main pipeline ─────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("SOC False Alarm Reduction - AI Model Training")
    print("=" * 60)

    # 1. Load alerts
    print("\n[1/6] Loading alerts from", ALERTS_FILE)
    alerts = []
    with open(ALERTS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    print(f"  Loaded {len(alerts)} real alerts")

    # 2. Generate synthetic data
    print("\n[2/6] Augmenting dataset with synthetic alerts...")
    synthetic = generate_synthetic_alerts(alerts, num_synthetic=400)
    all_alerts = alerts + synthetic
    random.shuffle(all_alerts)
    print(f"  Total dataset: {len(all_alerts)} alerts ({len(alerts)} real + {len(synthetic)} synthetic)")

    # 3. Extract features and labels
    print("\n[3/6] Extracting features...")
    records = []
    for alert in all_alerts:
        features = extract_features(alert)
        features["label"] = label_alert(alert)
        records.append(features)

    df = pd.DataFrame(records)

    # Encode categorical features
    le_rule = LabelEncoder()
    le_decoder = LabelEncoder()
    df["rule_id_enc"] = le_rule.fit_transform(df["rule_id"])
    df["decoder_name_enc"] = le_decoder.fit_transform(df["decoder_name"])

    # Save dataset
    df.to_csv(DATASET_FILE, index=False)
    print(f"  Dataset saved to {DATASET_FILE}")

    tp_count = (df["label"] == "true_positive").sum()
    fp_count = (df["label"] == "false_positive").sum()
    print(f"  True Positives: {tp_count} | False Positives: {fp_count}")

    # 4. Prepare training data
    print("\n[4/6] Training Random Forest model...")
    feature_cols = [
        "rule_level", "firedtimes",
        "has_attack_group", "has_sca_group", "has_syscheck_group",
        "has_web_group", "has_ossec_group", "num_groups",
        "has_mitre", "num_mitre_techniques",
        "is_manager_alert", "is_sca_decoder", "is_syscheck_decoder",
        "has_syscheck_data", "is_file_added", "is_file_modified",
        "is_syscheck_location", "is_log_location",
        "log_length", "has_suspicious_keywords",
        "has_tmp_path", "has_web_path",
        "rule_id_enc", "decoder_name_enc",
    ]

    X = df[feature_cols].values
    y = (df["label"] == "true_positive").astype(int).values  # 1 = TP, 0 = FP

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # Train
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    # 5. Evaluate
    print("\n[5/6] Evaluating model...")
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    # Cross-validation
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="f1")

    results = []
    results.append("=" * 60)
    results.append("MODEL EVALUATION RESULTS")
    results.append("=" * 60)
    results.append(f"\nDataset: {len(all_alerts)} alerts ({tp_count} TP, {fp_count} FP)")
    results.append(f"Train/Test split: 75/25 (stratified)")
    results.append(f"Model: Random Forest (100 trees, max_depth=10)")
    results.append(f"\n--- Test Set Metrics ---")
    results.append(f"Accuracy:  {acc:.4f}")
    results.append(f"Precision: {prec:.4f}")
    results.append(f"Recall:    {rec:.4f}")
    results.append(f"F1-Score:  {f1:.4f}")
    results.append(f"\n--- Confusion Matrix ---")
    results.append(f"              Predicted FP  Predicted TP")
    results.append(f"Actual FP:    {cm[0][0]:>10}  {cm[0][1]:>12}")
    results.append(f"Actual TP:    {cm[1][0]:>10}  {cm[1][1]:>12}")
    results.append(f"\n--- Cross-Validation (5-fold) ---")
    results.append(f"F1 scores: {[f'{s:.4f}' for s in cv_scores]}")
    results.append(f"Mean F1:   {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

    # Feature importance
    importances = model.feature_importances_
    feat_imp = sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True)
    results.append(f"\n--- Top 10 Feature Importances ---")
    for fname, imp in feat_imp[:10]:
        results.append(f"  {fname:<30} {imp:.4f}")

    # False alarm reduction
    total_fp_in_test = (y_test == 0).sum()
    correctly_filtered = cm[0][0]  # TN: correctly identified as FP
    reduction_rate = correctly_filtered / total_fp_in_test * 100 if total_fp_in_test > 0 else 0
    results.append(f"\n--- False Alarm Reduction ---")
    results.append(f"Total FP alerts in test set:     {total_fp_in_test}")
    results.append(f"Correctly filtered (True Neg):   {correctly_filtered}")
    results.append(f"False Alarm Reduction Rate:      {reduction_rate:.1f}%")
    results.append(f"Missed attacks (False Neg):       {cm[1][0]}")

    report = classification_report(y_test, y_pred, target_names=["false_positive", "true_positive"])
    results.append(f"\n--- Classification Report ---\n{report}")

    result_text = "\n".join(results)
    print(result_text)

    with open(RESULTS_FILE, "w") as f:
        f.write(result_text)
    print(f"\nResults saved to {RESULTS_FILE}")

    # 6. Save model
    print(f"\n[6/6] Saving model...")
    joblib.dump(model, MODEL_FILE)
    joblib.dump({"rule_id": le_rule, "decoder_name": le_decoder}, ENCODERS_FILE)

    feature_config = {
        "feature_columns": feature_cols,
        "attack_rules": list(ATTACK_RULES),
        "attack_groups": list(ATTACK_GROUPS),
        "model_file": "soc_rf_model.pkl",
        "encoders_file": "label_encoders.pkl",
    }
    with open(FEATURES_FILE, "w") as f:
        json.dump(feature_config, f, indent=2)

    print(f"  Model saved to {MODEL_FILE}")
    print(f"  Encoders saved to {ENCODERS_FILE}")
    print(f"  Feature config saved to {FEATURES_FILE}")
    print("\nDone!")


if __name__ == "__main__":
    main()
