#!/usr/bin/env python3
"""Standalone verifier for SYNAPZ improvement bundles (synapz-improvement-bundle/1).

    python -I verify.py <bundle_dir> [<bundle_dir> ...] [--public-key HEX] [--require-signed]
    python -I verify.py --all <dir>     # every */bundle under <dir>

Python 3.10+ standard library only. Ed25519 (RFC 8032) verification is
implemented below, so there is nothing to install. This file does not import
the SYNAPZ system. It re-implements, from the bundle format, every check the
reference verifier makes:

  integrity     manifest, file hashes, ledger + memory hash chains, chain heads and counts,
                every referenced payload present and content-addressed
  signatures    Ed25519 over every attestation digest and over the manifest statement;
                optional public-key pin
  policy        replay of every approved policy review from the initial policy (digests,
                versions, hard rules untouched); every allowed call re-evaluated under the
                policy in force at that moment
  skills        adopted skill content matches its approved digest; every demonstration is a
                successful, attested expert call with the same query and arguments
  metrics       every suite_metrics@1 result recomputed from the ledger
  held-out      held-out runs never feed a proposal; measured before the first / after the
                last adopted change
  facts         every memory fact re-verified against the ledger and payloads

Exit code 0 = every bundle VERIFIED with no warnings; 1 = any check failed or any warning.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any, Optional

FORMAT = "synapz-improvement-bundle/1"
GENESIS = "sha256:" + "0" * 64
REVIEW_TOOL, METRICS_TOOL, CHECK_TOOL = "policy_review@1", "suite_metrics@1", "task_check@1"
PROPOSE_TOOL, CHECKPOINT_TOOL, WRITE_TOOL = "skill_propose@1", "plan_checkpoint@1", "memory_write@1"
HARVEST_MINER = "skill_harvest"
HARNESS_TOOLS = (CHECK_TOOL, METRICS_TOOL)
MISSING = object()


# ---------------------------------------------------------------------------
# canonical JSON + hashing (sorted keys, compact separators, UTF-8, no NaN)
# ---------------------------------------------------------------------------

def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def chash(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def lookup(data: Any, path: str) -> Any:
    cur = data
    for part in path.split(".") if path else []:
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return MISSING
    return cur


# ---------------------------------------------------------------------------
# Ed25519 verification (RFC 8032 §5.1.7), pure Python
# ---------------------------------------------------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a: tuple, b: tuple) -> tuple:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    Dd = 2 * z1 * z2 % _P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s: int, pt: tuple) -> tuple:
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _equal(a: tuple, b: tuple) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(s: bytes) -> Optional[tuple]:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % _P)


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A, R = _decompress(public), _decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))


def _hexbytes(h: Any, n: int) -> Optional[bytes]:
    try:
        b = bytes.fromhex(h)
    except (TypeError, ValueError):
        return None
    return b if len(b) == n else None


# ---------------------------------------------------------------------------
# policy engine (gate semantics of the reference implementation)
# ---------------------------------------------------------------------------

def match(pattern: str, value: Optional[str]) -> bool:
    value = value or ""
    return pattern == "*" or pattern == value or (pattern.endswith("*") and value.startswith(pattern[:-1]))


class Deny(Exception):
    pass


def _targets(params: dict, tool: str, cap: str) -> bool:
    pats = [params["target"]] if params.get("target") is not None else list(params.get("targets", []))
    return any(match(p, tool) or match(p, cap) for p in pats)


def _agents(params: dict, agent: str) -> bool:
    return any(match(a, agent) for a in params.get("agents", ["*"]))


def evaluate(specs: list[dict], agent: str, tool: str, cap: str, args: dict, context: dict) -> tuple[bool, str]:
    """Return (allowed, gate). Dry-run semantics: approval gates abstain (approval happens at execution)."""
    granted = None
    for s in specs:
        kind, p, gid = s["kind"], s["params"], s["spec_id"]
        try:
            if kind == "allow":
                if match(p["agent"], agent) and any(match(t, tool) or match(t, cap) for t in p["targets"]):
                    granted = granted or gid
            elif kind == "deny":
                if _agents(p, agent) and any(match(t, tool) or match(t, cap) for t in p["targets"]):
                    return False, gid
            elif kind in ("limit", "range"):
                if _targets(p, tool, cap) and _agents(p, agent):
                    v = lookup(args, p["arg"])
                    if v is MISSING:
                        raise KeyError(p["arg"])
                    v = float(v)
                    if (v > float(p["max"])) if kind == "limit" else not float(p["min"]) <= v <= float(p["max"]):
                        return False, gid
            elif kind == "approval":
                continue  # dry run: the approver is consulted at execution, never here
            elif kind == "skill_confidence":
                if "skill_ref" in context:
                    approved = p.get("approved_digests")
                    if approved is not None and context.get("skill_digest") not in set(approved):
                        return False, gid
                    conf = context.get("skill_confidence")
                    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or conf < float(p["min"]):
                        return False, gid
            else:
                return False, gid  # unknown gate kind: fail closed
        except Exception:  # noqa: BLE001 - a failing gate denies (fail closed)
            return False, gid
    return (True, granted) if granted else (False, "default")


def policy_digest(version: int, specs: list[dict]) -> str:
    return chash({"version": version, "specs": specs})


def apply_change(version: int, specs: list[dict], change: dict) -> tuple[int, list[dict]]:
    specs = [dict(s) for s in specs]
    ids = [s["spec_id"] for s in specs]
    if change["op"] == "add":
        if change["spec"]["spec_id"] in ids:
            raise ValueError("spec already exists")
        specs.append(change["spec"])
    else:
        tid = change["target_spec_id"]
        if tid not in ids:
            raise ValueError(f"no spec {tid}")
        i = ids.index(tid)
        if specs[i].get("hard"):
            raise ValueError(f"hard rule {tid} cannot be changed")
        if change["op"] == "remove":
            specs.pop(i)
        elif change["op"] == "replace":
            new = change["spec"]
            if new["spec_id"] != tid and new["spec_id"] in ids:
                raise ValueError("spec already exists")
            specs[i] = new
        else:
            raise ValueError(f"unknown op {change['op']}")
    return version + 1, specs


# ---------------------------------------------------------------------------
# bundle checks
# ---------------------------------------------------------------------------

class Report:
    def __init__(self) -> None:
        self.checks: list[tuple[str, bool, str]] = []
        self.warnings: list[str] = []
        self.info: dict[str, Any] = {}

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append((name, bool(ok), detail))
        return bool(ok)

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c[1] for c in self.checks) and not self.warnings


def in_suite(ctx: dict, run: str) -> bool:
    return ctx.get("suite_run") == run or str(ctx.get("plan_id", "")).startswith(run + "/")


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _chain(rep: Report, name: str, entries: list[dict], body_key: str) -> bool:
    prev, bad = GENESIS, []
    for i, e in enumerate(entries):
        want = chash({"seq": e.get("seq"), "prev_hash": e.get("prev_hash"), body_key: e.get(body_key)})
        if e.get("seq") != i or e.get("prev_hash") != prev or e.get("entry_hash") != want:
            bad.append(i)
        prev = e.get("entry_hash")
    return rep.add(name, not bad, f"{len(entries)} entries, no gaps" if not bad else f"bad at seq {bad[:5]}")


def verify(path: Path, public_key: Optional[str] = None, require_signed: bool = False) -> Report:
    rep = Report()
    try:
        _verify(rep, path, public_key, require_signed or public_key is not None)
    except Exception as exc:  # noqa: BLE001 - anything unexpected fails the bundle
        rep.add("bundle_readable", False, f"{type(exc).__name__}: {exc}")
    return rep


def _verify(rep: Report, path: Path, public_key: Optional[str], require_signed: bool) -> None:
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    rep.add("manifest_format", manifest.get("format") == FORMAT, str(manifest.get("format")))
    for name, digest in manifest.get("files", {}).items():
        f = path / name
        rep.add(f"file:{name}", f.is_file() and hashlib.sha256(f.read_bytes()).hexdigest() == digest)
    ledger = _read_jsonl(path / "ledger.jsonl")
    memory = _read_jsonl(path / "memory.jsonl")
    if not (_chain(rep, "ledger_chain", ledger, "attestation") & _chain(rep, "memory_chain", memory, "record")):
        return
    rep.add("ledger_head", (ledger[-1]["entry_hash"] if ledger else GENESIS) == manifest.get("ledger_head")
            and len(ledger) == manifest.get("ledger_entries"), f"{len(ledger)} entries")
    rep.add("memory_head", (memory[-1]["entry_hash"] if memory else None) == manifest.get("memory_head")
            and len(memory) == manifest.get("memory_entries"))
    atts = [e["attestation"] for e in ledger]

    # payloads: every hash the ledger references must be present and content-addressed
    payloads: dict[str, Any] = {}
    missing, corrupt = [], []
    for a in atts:
        for h in (a.get("request_hash"), a.get("result_hash")):
            if not h or h in payloads:
                continue
            f = path / "payloads" / (h.replace(":", "_") + ".json")
            if not f.is_file():
                missing.append(h)
                continue
            obj = json.loads(f.read_text(encoding="utf-8"))
            if chash(obj) != h:
                corrupt.append(h)
            payloads[h] = obj
    for a in atts:
        req = payloads.get(a["request_hash"])
        if isinstance(req, dict) and chash({"tool_id": a["tool_id"], "args": req.get("args")}) != a["request_hash"]:
            corrupt.append(a["request_hash"])
    rep.add("payloads", not missing and not corrupt,
            f"{len(payloads)} referenced, {len(missing)} missing, {len(corrupt)} altered")
    if missing or corrupt:
        return
    _signatures(rep, manifest, atts, public_key, require_signed)

    tools: dict[str, str] = manifest["tools"]
    events = _events(ledger, payloads, tools)
    final = _replay(rep, path, manifest, ledger, payloads, tools)
    _metrics(rep, events, ledger, payloads)
    _heldout(rep, ledger, payloads)
    _facts(rep, memory, {a["attestation_id"]: (i, a) for i, a in enumerate(atts)}, payloads)
    rep.info["final_policy_version"] = final


def _signatures(rep: Report, manifest: dict, atts: list[dict], public_key: Optional[str], required: bool) -> None:
    signing = manifest.get("signing")
    if signing is None:
        if required:
            rep.add("signatures", False, "bundle is unsigned")
        else:
            rep.warnings.append("bundle is unsigned: integrity rests on the hash chains only")
        return
    pub = _hexbytes(signing.get("public_key"), 32) if isinstance(signing, dict) else None
    fingerprint = "ed25519:" + hashlib.sha256(pub).hexdigest()[:16] if pub else None
    if not rep.add("signing_key", signing.get("scheme") == "ed25519" and pub is not None
                   and signing.get("signer_id") == fingerprint, str(signing.get("signer_id"))):
        return
    rep.info["signer"] = signing["signer_id"]
    if public_key is not None:
        rep.add("signing_key_pinned", signing["public_key"].lower() == public_key.lower(), signing["signer_id"])
    else:
        rep.warnings.append(f"signing key not pinned: compare {signing['public_key']} with the published key "
                            "and pass --public-key")
    statement = {k: v for k, v in manifest.items() if k not in ("extra", "statement_signature")}
    sig = _hexbytes(manifest.get("statement_signature"), 64)
    rep.add("manifest_signature", sig is not None and ed25519_verify(pub, chash(statement).encode(), sig))
    bad = []
    for i, a in enumerate(atts):
        s = _hexbytes(a.get("signature"), 64)
        digest = chash({k: v for k, v in a.items() if k not in ("signature", "signer_id")})
        if a.get("signer_id") != signing["signer_id"] or s is None or not ed25519_verify(pub, digest.encode(), s):
            bad.append(i)
    rep.add("attestation_signatures", not bad, f"{len(atts) - len(bad)}/{len(atts)} valid"
            + (f"; bad at seq {bad[:5]}" if bad else ""))


def _numeric(value: Any, prefix: str = "") -> dict[str, float]:
    out: dict[str, float] = {}
    if isinstance(value, dict):
        for k, v in value.items():
            out.update(_numeric(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out.update(_numeric(v, f"{prefix}.{i}" if prefix else str(i)))
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        out[prefix] = float(value)
    return out


def _events(ledger: list[dict], payloads: dict, tools: dict) -> list[dict]:
    out = []
    for e in ledger:
        a = e["attestation"]
        ctx = a.get("context", {})
        kind = ("compensation" if "compensates" in ctx else "checkpoint" if a["tool_id"] == CHECKPOINT_TOOL
                else "proposal" if a["tool_id"] == PROPOSE_TOOL else "call")
        req = payloads.get(a["request_hash"])
        out.append({"seq": e["seq"], "a": a, "ctx": ctx, "kind": kind, "cap": tools.get(a["tool_id"]),
                    "args": req.get("args") if isinstance(req, dict) else None,
                    "human_approved": "approved by human" in a.get("policy_reason", "")})
    return out


def _replay(rep: Report, path: Path, manifest: dict, ledger: list[dict], payloads: dict, tools: dict) -> int:
    initial = json.loads((path / "policy_initial.json").read_text(encoding="utf-8"))
    version, specs = initial["version"], initial["specs"]
    rep.add("initial_policy", policy_digest(version, specs) == manifest.get("initial_policy_digest"))
    hard = {s["spec_id"] for s in specs if s.get("hard")}
    violations, chain_ok, adopted = [], True, 0
    for e in ledger:
        a = e["attestation"]
        cap = tools.get(a["tool_id"])
        req = payloads.get(a["request_hash"])
        if a["policy_decision"] == "allow" and cap is not None and isinstance(req, dict):
            ok, gate = evaluate(specs, a["agent_id"], a["tool_id"], cap, req.get("args") or {},
                                {**a.get("context", {}), "dry_run": True})
            if not ok:
                violations.append(f"seq {e['seq']} {a['agent_id']}->{a['tool_id']}: {gate}")
        if a["tool_id"] == REVIEW_TOOL and a["status"] == "ok":
            rec = payloads[a["result_hash"]]
            if rec["decision"] != "approve":
                chain_ok &= rec["policy_digest"] == policy_digest(version, specs)
                continue
            change = rec["change"]
            if change.get("target_spec_id") in hard:
                chain_ok = False
                violations.append(f"seq {e['seq']}: approved change touches hard rule {change['target_spec_id']}")
                continue
            chain_ok &= rec["from_version"] == version
            version, specs = apply_change(version, specs, change)
            chain_ok &= rec["policy_digest"] == policy_digest(version, specs) and rec["to_version"] == version
            adopted += 1
            if rec["miner"] == HARVEST_MINER:
                _skill(rep, rec, specs, {x["attestation"]["attestation_id"]: x["attestation"] for x in ledger},
                       payloads)
    rep.add("policy_chain", chain_ok and policy_digest(version, specs) == manifest.get("final_policy_digest"),
            f"replayed {adopted} approved changes to v{version}")
    rep.add("policy_conformance", not violations, "; ".join(violations[:3]))
    return version


def _skill(rep: Report, rec: dict, specs: list[dict], by_id: dict, payloads: dict) -> None:
    m = rec.get("metrics", {})
    skill = m.get("skill")
    if not isinstance(skill, dict):
        rep.add("skill_content", False, "review record carries no skill")
        return
    digest = chash(skill)
    approved = [d for s in specs if s["kind"] == "skill_confidence" for d in (s["params"].get("approved_digests") or [])]
    ok = digest == m.get("skill_digest") and digest in approved
    for d in skill.get("demonstrations", []):
        a = by_id.get(d.get("source_attestation") or "")
        ok &= (a is not None and a["status"] == "ok" and a["tool_id"] == skill.get("tool_id")
               and bool(a.get("context", {}).get("escalated"))
               and canonical(a["context"].get("task_query")) == canonical(d.get("query"))
               and canonical(payloads[a["request_hash"]]["args"]) == canonical(d.get("args")))
    rep.add(f"skill:{skill.get('skill_id')}@{skill.get('version')}", ok, "demonstrations traced to expert calls")


def compute_metrics(events: list[dict], run: str) -> dict:
    checks = [e["args"] for e in events if e["a"]["tool_id"] == CHECK_TOOL and e["a"]["status"] == "ok"
              and e["args"] and e["args"].get("suite_run") == run]
    work = [e for e in events if e["kind"] == "call" and e["a"]["tool_id"] not in HARNESS_TOOLS
            and not e["a"]["tool_id"].startswith("memory_") and in_suite(e["ctx"], run)]
    modes = [c["mode"] for c in checks]
    n, passed = len(checks), sum(bool(c["passed"]) for c in checks)
    out = {"tasks": n, "passed": passed, "success_rate": round(passed / n, 4) if n else 0.0,
           "autonomous": modes.count("autonomous"), "escalated": modes.count("escalated"),
           "failed": modes.count("failed") + modes.count("unexpected"),
           "probes_blocked": modes.count("denied_as_expected"), "policy_breaches": modes.count("unexpected"),
           "tool_calls": len(work), "denials": sum(e["a"]["status"] == "denied" for e in work),
           "errors": sum(e["a"]["status"] == "error" for e in work),
           "human_approvals": sum(e["human_approved"] for e in work)}
    # escalation correctness: only when the task checks carry the world's stated escalation rule
    judged = [c for c in checks if "needs_human" in c]
    if judged:
        approved_tasks = {task_of(e["ctx"]) for e in work if e["human_approved"]}
        human = [c["mode"] == "escalated" or c["task_id"] in approved_tasks for c in judged]
        need = [bool(c["needs_human"]) for c in judged]
        out.update(needs_human=sum(need),
                   escalation_correct=sum(a and b for a, b in zip(need, human)),
                   escalation_missed=sum(a and not b for a, b in zip(need, human)),
                   autonomy_correct=sum(not a and not b and bool(c["passed"]) for a, b, c in zip(need, human, judged)),
                   escalation_unnecessary=sum(not a and b for a, b in zip(need, human)))
    return out


def task_of(ctx: dict) -> Optional[str]:
    if ctx.get("task_id"):
        return str(ctx["task_id"])
    plan = str(ctx.get("plan_id", ""))
    return plan.split("/", 1)[1] if "/" in plan else None


def _metrics(rep: Report, events: list[dict], ledger: list[dict], payloads: dict) -> None:
    suites, ok = {}, True
    for e in ledger:
        a = e["attestation"]
        if a["tool_id"] == METRICS_TOOL and a["status"] == "ok":
            run = payloads[a["request_hash"]]["args"]["suite_run"]
            stored = payloads[a["result_hash"]]
            ok &= canonical(compute_metrics([x for x in events if x["seq"] < e["seq"]], run)) == canonical(stored)
            suites[run] = stored
    rep.info["suites"] = suites
    rep.add("metrics_recomputed", ok and bool(suites), f"{len(suites)} suite runs")


def _heldout(rep: Report, ledger: list[dict], payloads: dict) -> None:
    heldout = [r for r in rep.info.get("suites", {}) if r.startswith("heldout")]
    if not heldout:
        return
    atts = {e["attestation"]["attestation_id"]: (e["seq"], e["attestation"]) for e in ledger}
    leaks, approved = [], []
    for seq, a in atts.values():
        if a["tool_id"] != REVIEW_TOOL or a["status"] != "ok":
            continue
        rec = payloads[a["result_hash"]]
        if rec["decision"] == "approve":
            approved.append(seq)
        if "evidence" not in rec:
            leaks.append(f"review at seq {seq} records no evidence")
        skill = rec.get("metrics", {}).get("skill") or {}
        for src in list(rec.get("evidence", [])) + [d.get("source_attestation") for d in skill.get("demonstrations", [])]:
            hit = atts.get(src or "")
            if hit is None:
                leaks.append(f"evidence {src} not in ledger")
            elif any(in_suite(hit[1].get("context", {}), run) for run in heldout):
                leaks.append(f"evidence {src} comes from a held-out run")
    metrics_seq = {payloads[a["request_hash"]]["args"]["suite_run"]: s for s, a in atts.values()
                   if a["tool_id"] == METRICS_TOOL and a["status"] == "ok"}
    for run in heldout:
        first = min(s for s, a in atts.values() if in_suite(a.get("context", {}), run))
        if run.endswith("-before") and approved and metrics_seq[run] > min(approved):
            leaks.append(f"{run} not measured before the first adopted change")
        if run.endswith("-after") and approved and first < max(approved):
            leaks.append(f"{run} started before the last adopted change")
    rep.add("heldout_isolation", not leaks, f"{len(heldout)} held-out runs" + (f"; {leaks[:3]}" if leaks else ""))


def _facts(rep: Report, memory: list[dict], atts: dict, payloads: dict) -> None:
    facts: dict[str, dict] = {}
    status: dict[str, str] = {}
    bad: list[str] = []
    for e in memory:
        r = e["record"]
        if r["op"] == "assert":
            f = r["fact"]
            if chash({k: v for k, v in f.items() if k != "fact_id"}) != f.get("fact_id"):
                bad.append(f"fact {str(f.get('fact_id'))[:15]}: id does not match content")
            facts[f["fact_id"]], status[f["fact_id"]] = f, "active"
        elif r.get("fact_id") in facts:
            if status[r["fact_id"]] == "active":
                status[r["fact_id"]] = "retracted" if r["op"] == "retract" else "invalidated"
        else:
            bad.append(f"record targets unknown fact {r.get('fact_id')}")
    cache: dict[str, bool] = {}

    def ok(fid: str) -> bool:
        if fid in cache:
            return cache[fid]
        cache[fid] = False
        f = facts[fid]
        prov = f["provenance"]
        w = atts.get(prov.get("write_attestation") or "")
        good = w is not None and w[1]["tool_id"] == WRITE_TOOL and w[1]["status"] == "ok" \
            and w[1]["agent_id"] == prov.get("agent_id")
        if good:
            req = payloads[w[1]["request_hash"]]["args"]
            res = payloads[w[1]["result_hash"]]
            good = ((req["subject"], req["predicate"], req["scope"], req["source"])
                    == (f["subject"], f["predicate"], f["scope"], prov["source"])
                    and list(req.get("derived_from") or []) == list(prov.get("derived_from") or [])
                    and (prov["source"] != "tool_output" or req.get("source_attestation") == prov.get("attestation_id"))
                    and canonical(res["value"]) == canonical(f["value"]))
        if good and prov["source"] == "tool_output":
            src = atts.get(prov.get("attestation_id") or "")
            good = src is not None and src[1]["status"] == "ok"
            if good:
                out = lookup(payloads[src[1]["result_hash"]], prov.get("output_path") or "")
                good = out is not MISSING and canonical(out) == canonical(f["value"])
        elif good and prov["source"] == "derived":
            good = all(p in facts and ok(p) and status[p] == "active" for p in prov.get("derived_from", []))
        cache[fid] = good
        return good

    bad += [f"fact {fid[:15]} does not verify" for fid in facts if not ok(fid)]
    rep.info["cycles"] = [f["value"] for f in facts.values() if str(f["subject"]).startswith("cycle:")]
    rep.add("facts", not bad, f"{len(facts)} facts" + (f"; {bad[:3]}" if bad else ""))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Verify SYNAPZ improvement bundles from their files alone.")
    ap.add_argument("bundles", nargs="*", type=Path)
    ap.add_argument("--all", type=Path, help="verify every */bundle directory under this folder")
    ap.add_argument("--public-key", help="expected Ed25519 public key (hex); implies --require-signed")
    ap.add_argument("--require-signed", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="one line per bundle")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    bundles = list(args.bundles) + (sorted(args.all.glob("*/bundle")) if args.all else [])
    if not bundles:
        ap.error("give at least one bundle directory or --all DIR")
    all_ok = True
    for b in bundles:
        rep = verify(b, args.public_key, args.require_signed)
        all_ok &= rep.ok
        name = b.parent.name if b.name == "bundle" else b.name
        if args.quiet:
            failed = [c[0] for c in rep.checks if not c[1]]
            print(f"{'VERIFIED    ' if rep.ok else 'NOT VERIFIED'}  {name}"
                  + (f"  failed: {failed}" if failed else "") + (f"  warnings: {len(rep.warnings)}" if rep.warnings else ""))
            continue
        print(f"== {name}")
        for check, passed, detail in rep.checks:
            print(f"   {'PASS' if passed else 'FAIL'}  {check}" + (f"  ({detail})" if detail else ""))
        for w in rep.warnings:
            print(f"   WARN  {w}")
        for run, m in rep.info.get("suites", {}).items():
            print(f"         {run:22} passed {m['passed']}/{m['tasks']}  escalated {m['escalated']}  "
                  f"human approvals {m['human_approvals']}  probes blocked {m['probes_blocked']}")
        print(f"   {'VERIFIED' if rep.ok else 'NOT VERIFIED'}")
    print(f"{len(bundles)} bundle(s): " + ("ALL VERIFIED, no warnings" if all_ok else "NOT VERIFIED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
