# 🛡️ Provoke

**Continuous adversarial red-teaming for LLM applications — built to run in CI as a security gate.**

[![CI](https://github.com/Abraar02/provoke/actions/workflows/ci.yml/badge.svg)](https://github.com/Abraar02/provoke/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Most teams red-team their LLM features once, by hand, right before launch — then ship changes to prompts, models, and tools every week with no regression coverage. Provoke turns LLM red-teaming into an **automated, repeatable check**: it fires a battery of adversarial probes at any LLM endpoint, scores the responses, and **fails your build** when the attack-success-rate (ASR) crosses a threshold you set.

It maps every finding to the **[OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/)** and **[MITRE ATLAS](https://atlas.mitre.org/)**, and emits **SARIF** so vulnerabilities show up in the GitHub Security tab next to your SAST alerts.

> ⚖️ **Authorized testing only.** Provoke is a defensive tool for systems you own or are authorized to test. The bundled jailbreak probes measure *susceptibility to safety-bypass framing* (judged by whether the model refuses) and deliberately do **not** try to extract harmful content.

---

## Why it's different from a one-off jailbreak script

| One-off manual testing | Provoke |
|---|---|
| Run once, by hand, pre-launch | Runs on every PR / nightly in CI |
| "I jailbroke it" screenshot | Quantified ASR per OWASP category, trended over time |
| No pass/fail | Threshold **gate** that fails the build |
| Findings live in a doc | **SARIF** alerts in the GitHub Security tab |
| Hard-coded to one model | Pluggable **targets** (any OpenAI-compatible API) |

## Quickstart (no API key needed)

```bash
git clone https://github.com/Abraar02/provoke && cd provoke
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# Scan the built-in offline mock target:
cp provoke.example.yaml provoke.yaml
provoke scan -c provoke.yaml
```

You'll get a terminal summary plus `provoke-report/provoke.{md,json,sarif}`.

### Scan a real model

Point the target at any OpenAI-compatible endpoint and export your key:

```yaml
# provoke.yaml
target:
  type: openai_compat
  name: my-llm
  base_url: https://api.openai.com/v1
  model: gpt-4o-mini
  api_key_env: OPENAI_API_KEY
```

```bash
export OPENAI_API_KEY=sk-...
provoke scan -c provoke.yaml
```

## Example report

```
       Provoke scan: demo-mock-llm
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━┳━━━━━┳━━━━━┳━━━━━━┓
┃ Probe             ┃ OWASP  ┃ Sev ┃ Att ┃ Hit ┃ ASR  ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━╇━━━━━╇━━━━━╇━━━━━━┩
│ prompt_injection  │ LLM01  │ crit│   4 │   3 │  75% │
│ jailbreak         │ LLM01  │ high│   4 │   0 │   0% │
│ system_prompt_leak│ LLM07  │ med │   4 │   0 │   0% │
└───────────────────┴────────┴─────┴─────┴─────┴──────┘
Overall ASR: 25%  —  GATE FAILED
  ✗ LLM01:2025 Prompt Injection ASR 38% exceeds max 0%
```

The story the mock tells is realistic: a reasonably-aligned app that **resists direct jailbreaks** but **falls for indirect prompt injection** hidden inside untrusted data — the single most important LLM-app vulnerability class today.

## Use it as a GitHub Action

```yaml
# .github/workflows/llm-redteam.yml
- uses: Abraar02/provoke@v1
  with:
    config: provoke.yaml
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

The action runs the scan, writes the Markdown summary to the job summary, and uploads SARIF to code scanning.

## Architecture

```
            ┌─────────┐   attempts   ┌────────┐   responses   ┌───────────┐
  probes ──▶│ Probe   │─────────────▶│ Engine │──────────────▶│  Target   │
            │ registry│              │ (async)│◀──────────────│  adapter  │
            └─────────┘              └───┬────┘               └───────────┘
                                         │ results
                                         ▼
                                   ┌───────────┐   ┌──────────────────────┐
                                   │ Detectors │──▶│ Reporters             │
                                   │ (judges)  │   │ json · markdown · SARIF│
                                   └───────────┘   └──────────┬───────────┘
                                                              ▼
                                                      ASR gate → exit code
```

- **Targets** (`targets/`) — adapters to LLM endpoints. Built in: `mock` (offline), `openai_compat`.
- **Probes** (`probes/`) — attack generators that self-register and emit `Attempt`s tagged with OWASP/ATLAS. Payloads live in editable YAML under `data/payloads/`.
- **Detectors** (`detectors/`) — judges that score a response: `refusal`, `string_match` (canary).
- **Engine** (`engine.py`) — bounded-concurrency async runner with retries and per-call timeouts.
- **Reporting** (`reporting/`) — ASR aggregation, threshold gate, and JSON / Markdown / SARIF renderers.

## Add a probe (the contributor path)

For many attacks you only touch data — drop entries in `src/provoke/data/payloads/<probe>.yaml`. For a new attack class, add a module under `src/provoke/probes/` that calls `register(...)`:

```python
class MyProbe:
    id = "my_probe"
    name = "My attack"
    description = "..."
    def generate(self):
        for i, p in enumerate(load_payloads(self.id)):
            yield Attempt(probe_id=self.id, index=i, technique=p["technique"],
                          messages=(Message("user", p["prompt"]),),
                          owasp=OWASP.LLM01, atlas=Atlas.PROMPT_INJECTION,
                          severity=Severity.HIGH, detector="refusal")
register(MyProbe())
```

## Roadmap

- [ ] LLM-as-judge detector (semantic success scoring) — pluggable, off by default for hermetic CI
- [ ] Agentic / tool-abuse probes (OWASP LLM06 Excessive Agency)
- [ ] Multi-turn / crescendo attacks
- [ ] Baseline diffing (`provoke compare`) to flag *new* regressions per PR
- [ ] Anthropic + Bedrock native targets

## Security considerations

- **Reports may contain sensitive content.** The JSON report records the full prompt and model response for every attempt; a successful injection can surface data the target exfiltrated. Treat `provoke-report/` as a security artifact (it is git-ignored by default). The SARIF report omits response bodies.
- **`base_url` is restricted to http/https** to limit SSRF/LFI surface. Still, only point Provoke at endpoints you are authorized to test.
- **Secrets come from the environment only** (`api_key_env`); keys are never read from the config file and are masked in object reprs.
- A run where every attempt errors **fails the gate** — a scan that tested nothing never reports "secure".

## Development

```bash
uv pip install -e ".[dev]"
ruff check . && mypy src && pytest --cov
```

## License

MIT — see [LICENSE](LICENSE).
