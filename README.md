# Hybrid Detection Engineering Lab

## Overview
A cloud-native detection engineering project focused on building an end-to-end security pipeline in AWS. The objective was to emulate real-world adversary behavior and engineer custom detections using Infrastructure as Code (IaC) and portable detection standards (Sigma).

## Architecture
- **Infrastructure**: Provisioned entirely via **Terraform** for reproducible, zero-dollar budget deployment[cite: 3].
- **Pipeline**: CloudTrail logs -> S3 bucket -> SQS queue -> Splunk Enterprise[cite: 3].
- **Decoupling**: Used an SQS queue between S3 and Splunk to ensure log delivery resilience and prevent data loss during pipeline outages[cite: 3].

## Adversary Emulation
Used **Stratus Red Team** to detonate MITRE ATT&CK techniques against the environment[cite: 3]. Techniques included:
- **T1078.004**: Console login without MFA.
- **T1580/T1087**: EC2 enumeration/discovery.
- **T1136.003**: IAM persistence (creating admin user).
- **T1555/T1552**: Batch secret retrieval.
- **T1562.008**: Disabling CloudTrail logging.

## Detection Engineering
- **Sigma Rules**: Detections were authored in vendor-agnostic Sigma format to maintain portability across SIEM platforms[cite: 3].
- **SPL Conversion**: Rules were compiled into Splunk Processing Language (SPL) using `sigma-cli`[cite: 3].
- **Tuning**: Implemented false-positive filtering to exclude AWS service-role noise and allowlist known inventory tools[cite: 3].

## Alert Enrichment
Automated triage using a custom Python script that leverages `boto3` and `requests`[cite: 3].
- **Functionality**: Extracts source IPs from CloudTrail events and queries the **AbuseIPDB API** to score the reputation of the attacker[cite: 3].
- **Outcome**: Auto-generates enriched alert context, significantly reducing manual analyst triage time[cite: 3].

## Key Lessons
- **Behavior over Identity**: Detections are anchored on behavioral patterns (e.g., volume/variety of API calls) rather than static identity assumptions, effectively catching compromised administrative accounts[cite: 3].
- **Resilience**: Leveraging SQS/DLQ structures mirrors enterprise SOC ingestion pipelines, ensuring high availability of telemetry data[cite: 3].

## Repository Contents
- `/terraform`: AWS infrastructure configuration files.
- `/sigma-rules`: Detection logic in YAML format.
- `/spl-conversions`: Compiled detection queries for Splunk.
- `/scripts`: Python-based IP enrichment and alerting automation.
