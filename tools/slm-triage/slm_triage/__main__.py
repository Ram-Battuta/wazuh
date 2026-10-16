"""CLI entry point: ``python -m slm_triage --help``."""

import argparse
import logging
import os

from .backends import OpenAICompatBackend
from .indexer import LEVELS, IndexerFindingsSource, IndexerVerdictSink, make_client
from .service import TriageService


def env(name: str, default=None):
    return os.environ.get(f"SLM_TRIAGE_{name}", default)


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="slm_triage", description="SLM triage sidecar for Wazuh 5.x findings")
    g = p.add_argument_group("indexer")
    g.add_argument("--indexer-url", default=env("INDEXER_URL", "https://localhost:9200"))
    g.add_argument("--indexer-user", default=env("INDEXER_USER", "admin"))
    g.add_argument("--indexer-password", default=env("INDEXER_PASSWORD"))
    g.add_argument("--ca-certs", default=env("CA_CERTS"))
    g.add_argument("--insecure", action="store_true", help="skip TLS verification (lab use only)")
    g.add_argument("--findings-index", default=env("FINDINGS_INDEX", "wazuh-findings-v5-*"))
    g.add_argument("--verdict-index", default=env("VERDICT_INDEX", "wazuh-slm-triage-v5"))
    g.add_argument("--min-level", choices=LEVELS, default=env("MIN_LEVEL"),
                   help="only triage findings at or above this rule level")

    m = p.add_argument_group("model")
    m.add_argument("--model-url", default=env("MODEL_URL", "http://localhost:8080/v1"),
                   help="OpenAI-compatible base URL (llama-server, vLLM, Ollama, ...)")
    m.add_argument("--model", default=env("MODEL", "local-slm"))
    m.add_argument("--model-api-key", default=env("MODEL_API_KEY"))
    m.add_argument("--json-mode", choices=["schema", "object", "none"], default=env("JSON_MODE", "schema"),
                   help="schema = constrained decoding (llama.cpp, vLLM); object/none for servers without it")
    m.add_argument("--max-tokens", type=int, default=int(env("MAX_TOKENS", 512)))
    m.add_argument("--timeout", type=float, default=float(env("TIMEOUT", 60)))

    r = p.add_argument_group("runtime")
    r.add_argument("--batch-size", type=int, default=int(env("BATCH_SIZE", 32)))
    r.add_argument("--workers", type=int, default=int(env("WORKERS", 4)),
                   help="concurrent model requests; match the server's parallel slots")
    r.add_argument("--max-text", type=int, default=int(env("MAX_TEXT", 1500)))
    r.add_argument("--poll-interval", type=float, default=float(env("POLL_INTERVAL", 10)))
    r.add_argument("--checkpoint", default=env("CHECKPOINT", "./slm-triage-checkpoint.json"))
    r.add_argument("--once", action="store_true", help="process one batch and exit")
    r.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> None:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    client = make_client(args.indexer_url, args.indexer_user, args.indexer_password,
                         args.ca_certs, verify=not args.insecure)
    backend = OpenAICompatBackend(args.model_url, args.model, args.model_api_key,
                                  timeout=args.timeout, max_tokens=args.max_tokens, json_mode=args.json_mode)
    service = TriageService(IndexerFindingsSource(client, args.findings_index, args.min_level),
                            IndexerVerdictSink(client, args.verdict_index), backend,
                            args.checkpoint, batch_size=args.batch_size, workers=args.workers,
                            max_text=args.max_text)
    if args.once:
        service.run_once()
    else:
        service.run_forever(args.poll_interval)


if __name__ == "__main__":
    main()
