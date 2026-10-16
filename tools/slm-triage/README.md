# SLM triage sidecar for Wazuh 5.x

Runs your own small language models (1.5B–3B, fine-tuned or stock) over Wazuh findings and indexes a
structured verdict next to each one. Models run locally behind any OpenAI-compatible server; no data
leaves the host.

## Where it fits in Wazuh 5.x

```
agent ──► remoted (:1517) ──► engine (wazuh-manager-analysisd)
                               pre-filter → decoders → Geo/IOC enrich → post-filter → outputs
                                                   │
                                                   ▼
                              wazuh-indexer: wazuh-events-v5-<category>-*
                                                   │  Security Analytics detectors (Sigma rules)
                                                   ▼
                              wazuh-indexer: wazuh-findings-v5-<category>-*
                                                   │
                       ┌───────────────────────────┴────────────────────────┐
                       ▼                                                    ▼
         slm-triage (this tool)  ──► OpenAI-compatible SLM server     dashboard Alerting /
           reads findings              (llama-server, vLLM, Ollama)     Notifications /
           writes wazuh-slm-triage-v5 ◄────────────────────────────     Active Response monitors
```

Key facts about 5.x that shape the design (see `docs/ref/architecture.md`,
`docs/ref/modules/engine/architecture.md`, `docs/guide/migration/rules-4x-to-5x.md`):

- The engine has **no rules**. It decodes, normalizes to the Wazuh Common Schema and enriches.
- Detection runs **in the indexer**: Sigma detectors turn matching events into findings in
  `wazuh-findings-v5-<category>-*` (categories: security, system-activity, cloud-services, applications,
  network-activity, access-management, other, unclassified).
- `integratord` is gone, so there is no built-in "call an external service on each alert" hook. Actions
  are driven by dashboard Alerting monitors that query indices.

## Bolt-in points for a model

| # | Where | Latency budget | Status |
|---|-------|----------------|--------|
| 1 | **Findings sidecar** (this tool): read `wazuh-findings-v5-*`, write `wazuh-slm-triage-v5` | seconds; async | implemented |
| 2 | **Engine enrichment stage** (`src/engine/source/builder` helpers + `backend`), next to Geo/IOC | µs–ms per event, inline on every event | not suited to a 2–3B LLM; use for tiny classifiers (ONNX) gated by a pre-filter |
| 3 | **Indexer ML Commons** (separate `wazuh-indexer` repo): register the model as a remote connector, call it from ingest pipelines or detectors | per-document at index time | possible; couples the model to indexer upgrades |

Point 1 is the right place for generative models: findings are already a filtered, low-volume
stream, the sidecar needs no C++ changes, and it survives Wazuh upgrades as long as the findings schema
holds. Alerting monitors over `wazuh-slm-triage-v5` (e.g. `slm.verdict: true_positive AND
slm.severity: (high OR critical)`) close the loop into notifications or active response.

## Safety properties

- **Advisory only.** A verdict is a new document; the finding is never modified or suppressed.
- **Unparseable output becomes `needs_review`** with `slm.parse_error: true`, never a silent drop or a guessed `benign`.
- **Log text is untrusted.** It goes in as JSON between `<finding>` delimiters, and the model is told not to follow instructions in it. Treat `benign` verdicts as a hint, not as suppression. Don't wire a `benign` verdict to auto-close anything.
- **Constrained decoding.** `--json-mode schema` sends a JSON schema (`response_format: json_schema`), which llama.cpp and vLLM enforce at decode time.
- **No skipped findings.** If the model server is down, the checkpoint only advances over findings that were actually triaged.

## Run

```bash
pip install -r requirements.txt

# 1. Serve a model (any OpenAI-compatible server). llama.cpp example:
llama-server -m models/qwen2.5-1.5b-instruct-q4_k_m.gguf --port 8080 -c 4096 -np 4

# 2. Create the verdict index template once
curl -k -u admin:$PW -XPUT https://localhost:9200/_index_template/wazuh-slm-triage \
     -H 'Content-Type: application/json' -d @index-template.json

# 3. Run the sidecar
SLM_TRIAGE_INDEXER_PASSWORD=$PW python -m slm_triage \
    --indexer-url https://localhost:9200 --ca-certs /etc/wazuh-indexer/certs/root-ca.pem \
    --model-url http://localhost:8080/v1 --model qwen2.5-1.5b-q4 \
    --min-level medium --workers 4
```

Every flag has a `SLM_TRIAGE_<NAME>` environment variable equivalent; see `python -m slm_triage --help`.

Swapping models is just a matter of pointing `--model-url` / `--model` elsewhere. To compare models,
run two sidecars with different `--verdict-index` and `--checkpoint` values against the same findings.

## Test

```bash
pip install pytest
python -m pytest tests
```
