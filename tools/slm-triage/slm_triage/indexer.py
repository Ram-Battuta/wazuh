"""Wazuh Indexer I/O: read findings, write verdicts, persist a checkpoint."""

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple

LEVELS = ("low", "medium", "high", "critical")


@dataclass
class Checkpoint:
    """Position in the findings stream: last timestamp and the ids already seen at it."""
    timestamp: Optional[str] = None
    ids_at_timestamp: List[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str) -> "Checkpoint":
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return cls(data.get("timestamp"), list(data.get("ids_at_timestamp", [])))
        except FileNotFoundError:
            return cls()

    def save(self, path: str) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".checkpoint-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"timestamp": self.timestamp, "ids_at_timestamp": self.ids_at_timestamp}, f)
        os.replace(tmp, path)

    def advance(self, hits: Iterable[Dict[str, Any]]) -> None:
        for hit in hits:
            ts = hit["_source"].get("@timestamp")
            if ts != self.timestamp:
                self.timestamp, self.ids_at_timestamp = ts, []
            self.ids_at_timestamp.append(hit["_id"])


class FindingsSource(Protocol):
    def fetch(self, checkpoint: Checkpoint, size: int) -> List[Dict[str, Any]]: ...


class VerdictSink(Protocol):
    def write(self, docs: List[Tuple[str, Dict[str, Any]]]) -> None: ...


def build_query(checkpoint: Checkpoint, min_level: Optional[str], size: int) -> Dict[str, Any]:
    filters: List[Dict[str, Any]] = []
    if checkpoint.timestamp:
        filters.append({"range": {"@timestamp": {"gte": checkpoint.timestamp}}})
    if min_level:
        allowed = LEVELS[LEVELS.index(min_level):]
        filters.append({"terms": {"wazuh.rule.level": list(allowed)}})
    must_not = [{"ids": {"values": checkpoint.ids_at_timestamp}}] if checkpoint.ids_at_timestamp else []
    return {
        "size": size,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"bool": {"filter": filters, "must_not": must_not}},
    }


def make_client(url: str, user: Optional[str], password: Optional[str],
                ca_certs: Optional[str], verify: bool):
    from opensearchpy import OpenSearch  # imported lazily so unit tests do not need it
    return OpenSearch(
        hosts=[url],
        http_auth=(user, password) if user else None,
        use_ssl=url.startswith("https"),
        verify_certs=verify,
        ca_certs=ca_certs,
        ssl_show_warn=verify,
    )


class IndexerFindingsSource:
    def __init__(self, client, index_pattern: str, min_level: Optional[str]):
        self.client = client
        self.index_pattern = index_pattern
        self.min_level = min_level

    def fetch(self, checkpoint: Checkpoint, size: int) -> List[Dict[str, Any]]:
        body = build_query(checkpoint, self.min_level, size)
        resp = self.client.search(index=self.index_pattern, body=body,
                                  params={"ignore_unavailable": "true", "allow_no_indices": "true"})
        return resp["hits"]["hits"]


class IndexerVerdictSink:
    def __init__(self, client, index: str):
        self.client = client
        self.index = index

    def write(self, docs: List[Tuple[str, Dict[str, Any]]]) -> None:
        if not docs:
            return
        lines: List[Dict[str, Any]] = []
        for doc_id, doc in docs:
            # Finding id as document id: re-processing a finding overwrites, never duplicates.
            lines.append({"index": {"_index": self.index, "_id": doc_id}})
            lines.append(doc)
        resp = self.client.bulk(body=lines)
        if resp.get("errors"):
            failed = [i for i in resp["items"] if i.get("index", {}).get("error")]
            raise RuntimeError(f"bulk indexing failed for {len(failed)} verdicts: {failed[:1]}")
