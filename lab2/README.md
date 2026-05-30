# Lab 2 — Basic Anomaly Detection for Cybersecurity Logs

Unsupervised anomaly detection applied to synthetic authentication logs, with a focus on identifying MITRE ATT&CK techniques T1110 (Brute Force) and T1078 (Valid Accounts / compromised credentials).

## Overview

A synthetic dataset of 10,000 login events is generated with a 98/2 normal-to-anomaly split. Two attack archetypes are embedded:

- **T1110 — Brute Force:** high failed login counts (Poisson λ=12)
- **T1078 — Valid Accounts (Insider/Compromised):** logins at abnormal hours (~3 AM) with very short session durations

An **Isolation Forest** model is trained without labels, with `contamination=0.02` matching the known anomaly rate. Features are standardized with `StandardScaler` before fitting.

## Dataset

| Feature | Normal | Anomalous |
|---|---|---|
| `failed_logins` | Poisson(λ=0.2) | Poisson(λ=12.0) |
| `hour` | Normal(μ=13, σ=3) | Normal(μ=3, σ=1.5) |
| `session_duration_mins` | Normal(μ=120, σ=30) | Exponential(scale=10) |

## Steps

1. **Data Generation** — synthetic auth log construction with controlled normal/malicious distributions
2. **EDA** — box plots, histograms, and KDE plots comparing normal vs. attack feature distributions
3. **Anomaly Detection** — Isolation Forest trained on scaled features; predictions compared against ground-truth labels
4. **PCA Visualization** — 3D feature space reduced to 2D; anomalies visually cluster away from normal behavior, confirming model separation

## Key Result

The Isolation Forest cleanly isolates both attack archetypes in the PCA projection. Anomalies appear as distinct outlier groups branching away from the dense normal-behavior cluster, demonstrating that extreme feature values (high failed logins, off-hours activity, short sessions) are sufficient signal for unsupervised detection.

## Stack

- Python — `pandas`, `numpy`, `scikit-learn`, `matplotlib`, `seaborn`
- Notebook: `Authentication_Anomaly_Detection.ipynb`
