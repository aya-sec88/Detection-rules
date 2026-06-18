 # Detection Rules

![Validation](https://github.com/aya-sec88/detection-rules/actions/workflows/validate_toml.yml/badge.svg)
![Rules](https://img.shields.io/badge/rules-2-blue)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1059%20|%20T1105-red)

A collection of Elastic detection rules built from real attack scenarios, with automated validation and deployment via GitHub Actions.

## Rules

| Rule Name | Severity | MITRE Technique |
|---|---|---|
| Dropper Download Detected | High | T1105 - Ingress Tool Transfer |
| Reverse Shell Executed from /tmp | Critical | T1059.004 - Unix Shell |

## Structure
