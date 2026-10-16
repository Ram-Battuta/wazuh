"""Triage loop: fetch findings, run the model, index verdicts, advance the checkpoint."""

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .backends import BackendUnavailable, ModelBackend
from .finding import compact_finding, get_path
from .indexer import Checkpoint, FindingsSource, VerdictSink
from .prompt import build_messages
from .verdict import Verdict, parse_verdict

logger = logging.getLogger("slm_triage")


def triage_one(backend: ModelBackend, hit: Dict[str, Any], max_text: int) -> Tuple[Verdict, float]:
    messages = build_messages(compact_finding(hit["_source"], max_text))
    start = time.monotonic()
    text = backend.complete(messages)
    return parse_verdict(text), (time.monotonic() - start) * 1000


def verdict_doc(hit: Dict[str, Any], verdict: Verdict, model: str, latency_ms: float) -> Dict[str, Any]:
    src = hit["_source"]
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        # Same back-reference convention as wazuh-active-responses documents.
        "event": {"doc_id": hit["_id"], "index": hit.get("_index")},
        "finding": {
            "timestamp": src.get("@timestamp"),
            "rule": {
                "title": get_path(src, "wazuh.rule.title"),
                "level": get_path(src, "wazuh.rule.level"),
                "sigma_id": get_path(src, "wazuh.rule.sigma_id"),
            },
            "agent": {"id": get_path(src, "wazuh.agent.id"), "name": get_path(src, "wazuh.agent.name")},
            "integration": get_path(src, "wazuh.integration.name"),
            "category": get_path(src, "wazuh.integration.category"),
        },
        "slm": {**verdict.to_dict(), "model": model, "latency_ms": round(latency_ms, 1)},
    }


class TriageService:
    def __init__(self, source: FindingsSource, sink: VerdictSink, backend: ModelBackend,
                 checkpoint_path: str, batch_size: int = 32, workers: int = 4, max_text: int = 1500):
        self.source = source
        self.sink = sink
        self.backend = backend
        self.checkpoint_path = checkpoint_path
        self.checkpoint = Checkpoint.load(checkpoint_path)
        self.batch_size = batch_size
        self.workers = workers
        self.max_text = max_text

    def run_once(self) -> int:
        """Process one batch. Returns the number of findings triaged."""
        hits = self.source.fetch(self.checkpoint, self.batch_size)
        if not hits:
            return 0

        results: List[Optional[Tuple[Verdict, float]]] = [None] * len(hits)
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = [pool.submit(triage_one, self.backend, h, self.max_text) for h in hits]
            for i, fut in enumerate(futures):
                try:
                    results[i] = fut.result()
                except BackendUnavailable as exc:
                    logger.warning("model backend unavailable: %s", exc)
                except Exception:
                    logger.exception("triage failed for finding %s", hits[i]["_id"])
                    results[i] = (Verdict(summary="Triage error; see sidecar log.", parse_error=True), 0.0)

        # Only commit the contiguous prefix: a backend outage must not skip findings.
        done = 0
        while done < len(results) and results[done] is not None:
            done += 1
        if done == 0:
            return 0

        docs = [(h["_id"], verdict_doc(h, r[0], self.backend.name, r[1]))
                for h, r in zip(hits[:done], results[:done])]
        self.sink.write(docs)
        self.checkpoint.advance(hits[:done])
        self.checkpoint.save(self.checkpoint_path)
        logger.info("triaged %d findings (checkpoint %s)", done, self.checkpoint.timestamp)
        return done

    def run_forever(self, poll_interval: float = 10.0) -> None:
        while True:
            try:
                n = self.run_once()
            except Exception:
                logger.exception("triage cycle failed")
                n = 0
            # Drain backlogs quickly; sleep only when caught up or failing.
            if n < self.batch_size:
                time.sleep(poll_interval)
