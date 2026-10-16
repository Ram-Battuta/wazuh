"""SLM triage sidecar for Wazuh 5.x findings.

Reads findings produced by the indexer's Sigma detectors (``wazuh-findings-v5-*``),
asks a small language model served behind an OpenAI-compatible endpoint for a triage
verdict, and indexes the verdict into ``wazuh-slm-triage-v5`` so dashboard Alerting
monitors can act on it.
"""

__version__ = "0.1.0"
