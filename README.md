# Reducing SOC False Alarms through a Human-AI Collaboration Model

Final Project — Cyber Security Program

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Infrastructure Setup](#infrastructure-setup)
- [Attack Scenarios](#attack-scenarios)
- [Custom Detection Rules](#custom-detection-rules)
- [AI Model — False Alarm Classifier](#ai-model--false-alarm-classifier)
- [SOAR — Automated Response](#soar--automated-response)
- [Human-AI Collaboration Workflow](#human-ai-collaboration-workflow)
- [Results & Benchmarks](#results--benchmarks)
- [How to Run](#how-to-run)
- [Troubleshooting](#troubleshooting)

---

## Overview

Security Operations Centers (SOC) are overwhelmed by false alarms — studies show that up to 80-90% of SIEM alerts are false positives, causing alert fatigue and delayed incident response. This project implements a **Human-AI Collaboration Model** to reduce SOC false alarms by integrating:

1. **Wazuh SIEM** — open-source security monitoring platform for log collection, rule-based detection, and alert generation
2. **AI Classification Model** — Random Forest classifier trained on Wazuh alert data to automatically distinguish true attacks from benign noise
3. **SOAR (Security Orchestration, Automation, and Response)** — via Wazuh Active Response, enabling automated threat containment (IP blocking, account disabling) when attacks are confirmed

The system achieves an **88.5% false alarm reduction rate** on real Wazuh alerts while maintaining zero missed attacks, and demonstrates full automated response capability through the SOAR pipeline.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Azure Cloud VM                               │
│                                                                     │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐   │
│  │ Wazuh Agent   │───▶│  Wazuh Manager    │───▶│  Wazuh Indexer   │   │
│  │ (8.8.8.3)    │    │  (8.8.8.8)       │    │  (OpenSearch)    │   │
│  │              │    │                  │    │                  │   │
│  │ • nginx      │    │ • analysisd      │    │ • Alert storage  │   │
│  │ • syscheck   │    │ • custom rules   │    │ • Index/search   │   │
│  │ • log fwd    │    │ • active-response│    └──────────────────┘   │
│  └──────────────┘    │ • execd          │                          │
│                      └────────┬─────────┘    ┌──────────────────┐   │
│                               │              │ Wazuh Dashboard   │   │
│                               │              │ (port 443)       │   │
│                               ▼              │ • Visualization  │   │
│                      ┌────────────────┐      │ • Alert review   │   │
│                      │   AI Model     │      └──────────────────┘   │
│                      │ (Random Forest)│                             │
│                      │               │                             │
│                      │ • Classify     │      ┌──────────────────┐   │
│                      │ • ESCALATE /   │─────▶│ SOAR Pipeline    │   │
│                      │   SUPPRESS     │      │ Active Response  │   │
│                      └────────────────┘      │ • IP block       │   │
│                                              │ • Auto-unblock   │   │
│                                              └──────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

The architecture follows a standard SOC pipeline with an AI classification layer inserted between alert generation and human review. The Wazuh Agent collects logs from monitored endpoints and forwards events to the Wazuh Manager, which applies detection rules and triggers the AI model for classification. Confirmed threats are automatically handled by the SOAR pipeline via Active Response.

---

## Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| SIEM Platform | Wazuh (Manager, Agent, Indexer, Dashboard) | 4.14.5 |
| Containerization | Docker + Docker Compose | — |
| Cloud Platform | Microsoft Azure VM | — |
| AI/ML | scikit-learn (Random Forest Classifier) | — |
| Programming | Python 3, Bash | — |
| Network Isolation | Docker Bridge Network (8.8.8.0/24) | — |
| Log Source | nginx access logs, syscheck, syslog | — |
| SOAR Engine | Wazuh Active Response + custom-block.sh | — |
| Firewall | iptables (dynamic IP blocking) | — |

---

## Project Structure

```
SOC FP/
├── README.md                          # This documentation
├── docker-compose.yml                 # Docker infrastructure (4 containers)
├── Makefile                           # Build/deploy shortcuts
├── generate-indexer-certs.yml         # SSL certificate generation
├── alerts_raw.json                    # Raw Wazuh alert dataset (218 alerts)
├── custom-block.sh                    # SOAR active response script
│
├── ai_model/
│   ├── train_model.py                 # AI training pipeline
│   ├── wazuh_integration.py           # Wazuh-AI integration (batch + realtime)
│   ├── dataset.csv                    # Processed training dataset (618 alerts)
│   ├── soc_rf_model.pkl               # Trained Random Forest model
│   ├── label_encoders.pkl             # Feature encoders
│   ├── feature_config.json            # Feature configuration
│   ├── evaluation_results.txt         # Model evaluation metrics
│   └── output/
│       ├── true_positives.json        # Classified real attacks
│       ├── false_positives.json       # Classified false alarms
│       └── classification_summary.json # Summary statistics
│
├── config/
│   ├── certs.yml                      # Certificate configuration
│   ├── wazuh_cluster/
│   │   ├── wazuh_manager.conf         # Manager config (rules, active response)
│   │   └── local_rules.xml            # Custom detection rules (DDoS, Malware, Phishing)
│   ├── wazuh_agent/
│   │   ├── wazuh-agent-conf.xml       # Agent config (log monitoring)
│   │   └── build/                     # Agent Docker build files
│   ├── wazuh_indexer/
│   │   ├── wazuh.indexer.yml          # OpenSearch config
│   │   └── internal_users.yml         # User credentials
│   ├── wazuh_dashboard/
│   │   ├── opensearch_dashboards.yml  # Dashboard config
│   │   └── wazuh.yml                  # Dashboard-Wazuh connection
│   └── wazuh_indexer_ssl_certs/       # SSL certificates (auto-generated)
```

---

## Infrastructure Setup

### Prerequisites

- Docker and Docker Compose installed
- Minimum 4 GB RAM available for containers
- Azure VM (or any Linux host)

### Step 1: Generate SSL Certificates

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

### Step 2: Start All Services

```bash
docker compose up -d
```

This launches 4 containers on an isolated Docker bridge network (8.8.8.0/24):

| Container | Role | IP Address | Exposed Ports |
|-----------|------|-----------|--------------|
| wazuh.agent | Monitored endpoint | 8.8.8.3 | 8082→80 (nginx) |
| wazuh.manager | SIEM engine + SOAR | 8.8.8.8 | 1514, 1515, 514, 55000 |
| wazuh.indexer | Alert storage (OpenSearch) | auto | 9200 |
| wazuh.dashboard | Web UI | auto | 443→5601 |

### Step 3: Access Dashboard

Open `https://localhost:443` in a browser. Default credentials: `admin` / `SecretPassword`.

### Step 4: Deploy SOAR Script

```bash
# Copy custom-block.sh to manager container
docker cp custom-block.sh socfp-wazuh.manager-1:/var/ossec/active-response/bin/custom-block.sh

# Set permissions
docker exec socfp-wazuh.manager-1 chmod 750 /var/ossec/active-response/bin/custom-block.sh
docker exec socfp-wazuh.manager-1 chown root:wazuh /var/ossec/active-response/bin/custom-block.sh

# Install iptables for IP blocking
docker exec socfp-wazuh.manager-1 yum install -y iptables
```

> **Note:** After any `docker compose down && docker compose up`, iptables and custom-block.sh must be redeployed.

---

## Attack Scenarios

Three categories of attacks are simulated and detected:

### 1. DDoS Attack (Rule 100001)

Simulates a volumetric HTTP flood against the agent's nginx web server.

```bash
# Run from manager container — flood agent's nginx with 200 requests
docker exec socfp-wazuh.manager-1 bash -c \
  'for i in $(seq 1 200); do curl -s http://8.8.8.3/ > /dev/null; done'
```

**Detection logic:** Rule 100001 triggers when the same source IP generates more than 50 HTTP requests within 10 seconds (frequency-based correlation).

**MITRE ATT&CK:** T1498 — Network Denial of Service

### 2. Malware Attack (Rules 100010–100013)

Simulates malware file drops and suspicious file operations on the monitored agent.

```bash
# Drop suspicious file in /tmp (triggers rule 100010)
docker exec socfp-wazuh.agent-1 bash -c 'echo "malicious" > /tmp/backdoor.sh'

# Drop webshell in nginx directory (triggers rule 100011)
docker exec socfp-wazuh.agent-1 bash -c \
  'echo "<?php system(\$_GET[cmd]);?>" > /usr/share/nginx/html/shell.php'

# Create file with suspicious name pattern (triggers rule 100012)
docker exec socfp-wazuh.agent-1 bash -c 'echo "payload" > /tmp/reverse_shell.sh'

# Change file permissions to executable (triggers rule 100013)
docker exec socfp-wazuh.agent-1 bash -c 'chmod +x /tmp/backdoor.sh'
```

**Detection logic:** Rules match syscheck (File Integrity Monitoring) events based on file paths (/tmp, /var/www, /usr/share/nginx) and suspicious filename patterns (shell, backdoor, exploit, payload, etc.).

**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter), T1505.003 (Web Shell), T1204 (User Execution), T1222 (File and Directory Permissions Modification)

### 3. Social Engineering / Phishing (Rules 100020–100023)

Simulates phishing email indicators, access to phishing URLs, C2 callbacks, and suspicious file downloads.

```bash
# Simulate phishing email in mail log (triggers rule 100020)
docker exec socfp-wazuh.agent-1 bash -c \
  'echo "$(date) mail: phishing suspicious-link from attacker@evil.com" >> /var/spool/mail/user'

# Simulate access to phishing URL (triggers rule 100021)
docker exec socfp-wazuh.agent-1 bash -c \
  'echo "192.168.1.100 - - [24/Jun/2026:10:00:00 +0000] \"GET /fake-login HTTP/1.1\" 200 1234" >> /var/log/nginx/access.log'

# Simulate C2 callback after phishing (triggers rule 100022)
docker exec socfp-wazuh.agent-1 bash -c \
  'logger "curl http://10.20.30.40/payload executed by compromised user"'

# Simulate suspicious file download (triggers rule 100023)
docker exec socfp-wazuh.agent-1 bash -c 'echo "malware" > /tmp/update.exe'
```

**Detection logic:** Rules use regex pattern matching on log content for phishing keywords, suspicious URLs, outbound connections to IP addresses (C2 indicators), and executable file extensions (.exe, .bat, .ps1, .vbs, etc.).

**MITRE ATT&CK:** T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link), T1071 (Application Layer Protocol), T1204.002 (Malicious File)

---

## Custom Detection Rules

All custom rules are defined in `config/wazuh_cluster/local_rules.xml` and deployed to the manager at `/var/ossec/etc/rules/local_rules.xml`.

| Rule ID | Level | Category | Description | MITRE |
|---------|-------|----------|-------------|-------|
| 100001 | 12 | DDoS | HTTP flood detected (>50 req/10s from same IP) | T1498 |
| 100010 | 12 | Malware | Suspicious file created in /tmp | T1059 |
| 100011 | 13 | Malware | File created in web directory (webshell) | T1505.003 |
| 100012 | 14 | Malware | File with suspicious name pattern | T1204 |
| 100013 | 10 | Malware | File permissions changed (staging) | T1222 |
| 100020 | 12 | Phishing | Phishing email detected in mail log | T1566.001 |
| 100021 | 12 | Phishing | Access to phishing URL | T1566.002 |
| 100022 | 13 | Phishing | Suspicious outbound connection (C2) | T1071 |
| 100023 | 12 | Phishing | Suspicious file downloaded | T1204.002 |

Rules are organized into three rule groups: `web,nginx,attack` (DDoS), `malware,syscheck,attack` (Malware), and `social_engineering,phishing,attack` (Social Engineering).

---

## AI Model — False Alarm Classifier

### Problem Statement

In a typical SOC environment, analysts receive hundreds or thousands of alerts daily. The vast majority are false positives — benign system events, routine checks, and noise. This leads to alert fatigue, where real threats get missed because analysts cannot effectively triage the volume.

### Approach

We train a **Random Forest Classifier** on labeled Wazuh alert data to automatically distinguish between true positive alerts (real attacks) and false positive alerts (benign noise).

### Feature Engineering

The model extracts 24 features from each Wazuh alert JSON:

| Feature Category | Features | Description |
|-----------------|----------|-------------|
| Rule metadata | `rule_level`, `rule_id_enc`, `firedtimes` | Severity level, encoded rule ID, trigger count |
| Group analysis | `has_attack_group`, `has_sca_group`, `has_syscheck_group`, `has_web_group`, `has_ossec_group`, `num_groups` | Presence of specific rule groups and total group count |
| MITRE ATT&CK | `has_mitre`, `num_mitre_techniques` | Whether MITRE mapping exists and technique count |
| Agent context | `is_manager_alert` | Whether alert originated from manager (000) vs agent |
| Decoder | `decoder_name_enc`, `is_sca_decoder`, `is_syscheck_decoder` | Log decoder identification |
| File integrity | `has_syscheck_data`, `is_file_added`, `is_file_modified` | Syscheck event metadata |
| Location | `is_syscheck_location`, `is_log_location` | Alert source location |
| Log content | `log_length`, `has_suspicious_keywords`, `has_tmp_path`, `has_web_path` | NLP-style text features from full_log |

### Training Pipeline

```
alerts_raw.json (218 real alerts)
        │
        ▼
  Data Augmentation (400 synthetic alerts)
        │
        ▼
  Total Dataset: 618 alerts (225 TP, 393 FP)
        │
        ▼
  Feature Extraction (24 features)
        │
        ▼
  Train/Test Split (75/25, stratified)
        │
        ▼
  Random Forest (100 trees, max_depth=10, balanced weights)
        │
        ▼
  Model Evaluation + Save
```

**Labeling strategy:** Alerts matching custom attack rule IDs (100001, 100010–100013, 100020–100023) are labeled as `true_positive`. All other alerts (SCA checks, routine syscheck, system events) are labeled as `false_positive`.

**Data augmentation:** To increase dataset size and robustness, 400 synthetic alerts are generated using templates with randomized variations (different filenames, IP addresses, firedtimes values).

### Top Feature Importances

| Rank | Feature | Importance |
|------|---------|-----------|
| 1 | `has_mitre` | 0.1614 |
| 2 | `num_mitre_techniques` | 0.1532 |
| 3 | `has_attack_group` | 0.1510 |
| 4 | `num_groups` | 0.1363 |
| 5 | `rule_level` | 0.1323 |
| 6 | `rule_id_enc` | 0.0889 |
| 7 | `log_length` | 0.0576 |
| 8 | `is_manager_alert` | 0.0393 |
| 9 | `decoder_name_enc` | 0.0210 |
| 10 | `is_sca_decoder` | 0.0139 |

The most discriminative features are MITRE ATT&CK mapping presence, attack group membership, and rule severity level — which aligns with security domain knowledge since real attacks are more likely to have MITRE mappings and higher severity levels.

### Integration with Wazuh

The integration script (`ai_model/wazuh_integration.py`) supports two operational modes:

- **Batch mode** (`--batch`): Processes the full `alerts_raw.json` file, classifying all alerts and generating output reports
- **Real-time mode** (`--realtime`): Tails the alerts file and classifies new alerts as they arrive, mimicking production SOC operation

For each alert, the classifier outputs:
- **ESCALATE** — true positive, forwarded to human analyst for review
- **SUPPRESS** — false positive, logged but filtered from the main alert feed

---

## SOAR — Automated Response

### Overview

SOAR (Security Orchestration, Automation, and Response) is implemented using Wazuh Active Response. When specific attack rules trigger, the manager automatically executes `custom-block.sh` to contain the threat without human intervention.

### Active Response Configuration

Three automated response triggers are configured in `wazuh_manager.conf`:

| Trigger Rule | Attack Type | Action | Timeout |
|-------------|------------|--------|---------|
| 100001 | DDoS | Block attacker IP via iptables | 300s (5 min) |
| 100022 | C2 Callback | Block C2 destination IP | 600s (10 min) |
| 100011, 100012 | Malware (webshell, suspicious file) | Block source IP | 600s (10 min) |

### Wazuh 4.x Active Response Protocol

The `custom-block.sh` script implements the Wazuh 4.x stateful active response protocol:

```
┌─────────┐                    ┌───────────────┐
│  execd   │───── alert JSON ──▶│ custom-block  │
│          │                    │    .sh        │
│          │◀── check_keys ─────│               │
│          │                    │               │
│          │── continue/abort ─▶│               │
│          │                    │ Execute:      │
│          │                    │ • iptables    │
│          │                    │   DROP rule   │
│          │                    │ • Log action  │
└─────────┘                    └───────────────┘
```

1. `execd` sends the alert JSON via STDIN (includes source IP, rule ID, command type)
2. Script parses the JSON using Python3, extracts `srcip`, `rule_id`, and `command` (add/delete)
3. Script sends `check_keys` message back to `execd` via STDOUT
4. `execd` responds with `continue` or `abort`
5. On `continue`: script executes the iptables command
6. On timeout: `execd` automatically sends a `delete` command to remove the block

### Key Configuration Detail

The active response uses `<location>server</location>` because the `custom-block.sh` script resides on the **manager** container, while alerts originate from the **agent**. Using `<location>local</location>` would incorrectly attempt to run the script on the agent where it does not exist.

### Proven Results

Active response log from successful SOAR execution:

```
Wed Jun 24 16:09:10 UTC 2026 custom-block.sh received command
Wed Jun 24 16:09:10 UTC 2026 ACTION: add srcip:8.8.8.8 rule:100001
Wed Jun 24 16:14:11 UTC 2026 custom-block.sh received command
Wed Jun 24 16:14:11 UTC 2026 ACTION: delete srcip:8.8.8.8 rule:100001
Wed Jun 24 16:15:10 UTC 2026 custom-block.sh received command
Wed Jun 24 16:15:10 UTC 2026 ACTION: add srcip:8.8.8.8 rule:100001
Wed Jun 24 16:15:10 UTC 2026 BLOCKED 8.8.8.8 via iptables (rule:100001)
```

This log demonstrates the complete automated SOAR cycle: DDoS detected → IP blocked → timeout expired → IP unblocked → new DDoS detected → IP blocked again.

---

## Human-AI Collaboration Workflow

The system implements a tiered collaboration between AI automation and human analysts:

```
  Wazuh Alert Generated
         │
         ▼
  ┌──────────────┐
  │  AI Classifier│
  │  (Random      │
  │   Forest)     │
  └──────┬───────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
 TRUE_POS  FALSE_POS
    │         │
    ▼         ▼
 ESCALATE  SUPPRESS
    │         │
    ▼         ▼
 Human     Auto-logged,
 Analyst   filtered from
 Review    main feed
    │
    ▼
 Confirm / Override
    │
    ▼
 SOAR Action
 (if confirmed attack)
```

**Tier 1 — AI Automated:** All incoming alerts pass through the Random Forest classifier. False positives are automatically suppressed (88.5% of alerts), dramatically reducing the analyst's workload.

**Tier 2 — Human Review:** Only true positives (11.5% of alerts) are escalated to human analysts. This focused set allows analysts to make faster, more accurate decisions.

**Tier 3 — SOAR Automated Response:** For high-confidence attack detections matching specific rule IDs, the SOAR pipeline executes automated containment (IP blocking) without waiting for human intervention. The analyst can review and override after the fact.

---

## Results & Benchmarks

### AI Model Performance

| Metric | Value |
|--------|-------|
| Test Accuracy | 100.0% |
| Precision | 100.0% |
| Recall | 100.0% |
| F1-Score | 100.0% |
| Cross-Validation (5-fold) Mean F1 | 100.0% |

### Confusion Matrix (Test Set)

|  | Predicted FP | Predicted TP |
|--|-------------|-------------|
| **Actual FP** | 99 | 0 |
| **Actual TP** | 0 | 56 |

### Real-World Alert Classification

| Metric | Value |
|--------|-------|
| Total alerts processed | 218 |
| True positives (real attacks) | 25 (11.5%) |
| False positives (noise) | 193 (88.5%) |
| **False alarm reduction rate** | **88.5%** |
| Alerts requiring human review | 25 |
| Alerts auto-suppressed | 193 |

### SOAR Performance

| Metric | Value |
|--------|-------|
| Attack detection to block time | < 1 second |
| Auto-unblock after timeout | Verified working |
| Supported attack types | DDoS, Malware, C2 Callback |
| Block mechanism | iptables DROP (INPUT + FORWARD) |

### Impact Summary

Without the AI model, a SOC analyst would need to review all 218 alerts. With the model, only 25 alerts require human attention — a reduction of **88.5%** in analyst workload. Combined with SOAR automated response, confirmed attacks are contained in under 1 second without human intervention.

---

## How to Run

### 1. Start Infrastructure

```bash
# Generate certificates (first time only)
docker compose -f generate-indexer-certs.yml run --rm generator

# Start all containers
docker compose up -d

# Wait ~1 minute for services to initialize
```

### 2. Deploy SOAR Script

```bash
docker cp custom-block.sh socfp-wazuh.manager-1:/var/ossec/active-response/bin/custom-block.sh
docker exec socfp-wazuh.manager-1 chmod 750 /var/ossec/active-response/bin/custom-block.sh
docker exec socfp-wazuh.manager-1 chown root:wazuh /var/ossec/active-response/bin/custom-block.sh
docker exec socfp-wazuh.manager-1 yum install -y iptables
```

### 3. Run Attack Simulations

```bash
# DDoS
docker exec socfp-wazuh.manager-1 bash -c \
  'for i in $(seq 1 200); do curl -s http://8.8.8.3/ > /dev/null; done'

# Malware
docker exec socfp-wazuh.agent-1 bash -c 'echo "malicious" > /tmp/backdoor.sh'

# Social Engineering
docker exec socfp-wazuh.agent-1 bash -c \
  'logger "curl http://10.20.30.40/payload executed by compromised user"'
```

### 4. Train AI Model

```bash
cd ai_model
pip install scikit-learn pandas numpy joblib
python train_model.py
```

### 5. Run AI Classification

```bash
# Batch mode — process all existing alerts
python ai_model/wazuh_integration.py --batch

# Real-time mode — monitor for new alerts
python ai_model/wazuh_integration.py --realtime
```

### 6. Verify SOAR

```bash
# Check active response log
docker exec socfp-wazuh.manager-1 cat /var/ossec/logs/active-responses.log

# Verify iptables rules (requires iptables installed)
docker exec socfp-wazuh.manager-1 iptables -L -n
```

---

## Troubleshooting

### iptables not found after container restart

```bash
docker exec socfp-wazuh.manager-1 yum install -y iptables
```

Container restarts wipe installed packages. Reinstall iptables after every `docker compose down/up`.

### custom-block.sh not executing

1. Verify the script exists and has correct permissions:
   ```bash
   docker exec socfp-wazuh.manager-1 ls -la /var/ossec/active-response/bin/custom-block.sh
   ```
   Expected: `-rwxr-x--- root wazuh`

2. Check that `<location>server</location>` is set in `wazuh_manager.conf` (not `local`)

3. Check execd logs:
   ```bash
   docker exec socfp-wazuh.manager-1 cat /var/ossec/logs/ossec.log | grep -i "execd\|active-response"
   ```

### DDoS rule not triggering

The DDoS simulation must target the **agent's nginx** (8.8.8.3), not any other IP. The curl must be run from the manager container so the source IP is 8.8.8.8, and the requests reach the agent's access log which Wazuh monitors.

### Agent not connecting

Verify the agent can reach the manager:
```bash
docker exec socfp-wazuh.agent-1 ping -c 3 8.8.8.8
```

Check agent status from manager:
```bash
docker exec socfp-wazuh.manager-1 /var/ossec/bin/agent_control -l
```
