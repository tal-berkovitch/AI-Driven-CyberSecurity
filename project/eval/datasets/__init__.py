"""Real-dataset adapters for the evaluation harness.

The headline real dataset is CIC-Bell-DNS-EXF-2021 (DNS exfiltration/tunneling).
Adapters turn a real dataset into the SAME ``FeatureRecord`` rows the live system
produces, so the detector backends are benchmarked on real data with zero
feature-schema divergence (see ARCHITECTURE.md §6).
"""
