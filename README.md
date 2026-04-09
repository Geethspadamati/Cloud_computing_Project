# Cloud_computing_Project
Detecting Data Leaks via SQL Injection : AWS

---

## Overview

This project implements a cloud-native system on **Amazon Web Services (AWS)** to simulate, detect, and respond to SQL injection attacks that cause data leaks. SQL injection is one of the most critical web vulnerabilities (OWASP Top 10), and this project demonstrates how AWS services can be combined into a real-time detection and response pipeline.

---

## Team

| Person | Role | Layer | AWS Services |
|--------|------|-------|--------------|
| Person 1 | Attack Simulation & Target Setup | Attack Layer | EC2 + RDS (MySQL) |
| Person 2 | Network Defense | App/Network Layer | WAF + API Gateway + VPC Flow Logs + Shield |
| Person 3 | Detection Engine | Detection Layer | Lambda + GuardDuty |
| Person 4 | Logging & Data Pipeline | Logging Layer | CloudWatch + S3 + Kinesis |
| Person 5 | Alerting, Dashboard & Reporting | Alerting/UI Layer | SNS + Amplify + Security Hub |

---

## Architecture

The system is divided into **5 layers**, each owned by one team member:

```
[ Attacker EC2 ] ──► [ API Gateway ] ──► [ WAF ] ──► [ Web App EC2 ] ──► [ RDS MySQL ]
                                           │
                                    [ VPC Flow Logs ]
                                           │
                                   [ Kinesis Stream ]
                               ┌──────────┴──────────┐
                          [ Lambda ]            [ S3 Archive ]
                        (Detection)           (Firehose)
                               │
                    ┌──────────┴──────────┐
               [ SNS Alert ]       [ CloudWatch ]
                    │                    │
             [ Email/SMS ]        [ Dashboard ]
                    │
          [ Amplify Dashboard ]
                    │
           [ Security Hub ]
```

**Data flow:** Attack → API Gateway → WAF → App → Kinesis → Lambda (detect) → SNS (alert) → Dashboard

---

## Project Structure

```
/
├── README.md                   ← You are here (project overview)
├── attack-layer/
│   └── README.md               ← Person 1: EC2 attacker VM + RDS setup
├── network-defense/
│   └── README.md               ← Person 2: WAF + API Gateway + VPC + Shield
├── detection-engine/
│   └── README.md               ← Person 3: Lambda detection + GuardDuty
├── logging-pipeline/
│   └── README.md               ← Person 4: CloudWatch + S3 + Kinesis
└── alerting-dashboard/
    └── README.md               ← Person 5: SNS + Amplify + Security Hub
```

---

## How the Attack Pipeline Works

1. **Person 1** launches an Ubuntu EC2 attacker VM and runs SQLMap against a deliberately vulnerable Flask web app backed by an RDS MySQL database.
2. **Person 2** places AWS WAF and API Gateway in front of the app. WAF blocks known SQLi patterns; API Gateway rate-limits traffic.
3. **Person 3** deploys a Python Lambda function that reads WAF logs from Kinesis in real time, applies regex to detect SQLi patterns, and classifies severity (LOW / MEDIUM / HIGH / CRITICAL).
4. **Person 4** sets up Kinesis Data Streams to pipe all WAF logs to Lambda and S3. CloudWatch dashboards show live attack metrics.
5. **Person 5** configures SNS to send email/SMS alerts on HIGH/CRITICAL findings, deploys a React dashboard on Amplify, and enables Security Hub for compliance scoring.

---

## 10-Day Timeline

| Day | Milestone |
|-----|-----------|
| 1 | AWS accounts, IAM roles, shared VPC, GitHub repo |
| 2 | Vulnerable web app live, RDS populated, WAF rules active |
| 3 | First SQLMap attack, Kinesis stream, Lambda deployed, GuardDuty on |
| 4 | Lambda running on live traffic, SNS alerts configured |
| 5 | End-to-end pipeline tested, S3 archiving, second attack run |
| 6 | React dashboard on Amplify, Security Hub, CloudWatch dashboard |
| 7 | Full demo video recorded, results captured |
| 8–9 | Report written and peer-reviewed |
| 10 | Final submission |

---

## Technology Stack

| Category | Technology |
|----------|------------|
| Infrastructure as Code | Terraform / AWS CloudFormation |
| Vulnerable Web App | Python Flask / DVWA |
| Attack Tools | SQLMap + Burp Suite Community |
| Detection Logic | Python Lambda + `re` + `boto3` |
| Dashboard Frontend | React + Chart.js |
| Report | LaTeX / Word (.docx) |
| Demo Recording | OBS Studio |
