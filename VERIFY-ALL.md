# How to re-check every verified run

Each folder `<run>/bundle` next to this file is a self-contained, **Ed25519-signed** record of one
governed improvement cycle. A bundle holds the hash-chained ledger of every tool call, approval,
review and metric, the request and result payloads, the memory log, the starting policy, a signed
manifest, and `explorer.html`. You do not need to trust the people who produced it.

## The signing key (check this first)

```text
scheme      ed25519
signer_id   ed25519:0b6288c3f486c397
public_key  51ad6d3eccfae04958c0248edc60ac0a818b0584dc3878d6bfe4776d2ec8f81a
```

Every attestation in every bundle, and every bundle manifest, must verify against this public key. A
signature only means something if the key came from the publisher. Compare this key with the one
announced on the publisher's own channel, not only with this file.

The `signer_id` is `ed25519:` followed by the first 16 hex digits of SHA-256 over the raw 32-byte public
key, so you can recompute it.

## The bundles

On Windows, each bundle has hundreds of payload files with 64-character names. Unpack or clone into a
short path, such as `C:`, or enable long paths first (`git config --global core.longpaths true`).

| Run | What it shows |
|---|---|
| `refund-desk` | tickets, FX quotes, payouts: learned ticket skill, payout-approval threshold, explicit deny |
| `support-triage` | incident routing: learned routing skill, explicit deny |
| `data-validation` | quarantine records, publish releases: learned quarantine skill, publish-approval threshold |
| `reporting` | 3-step plans (fetch → convert → publish): approval threshold, mined FX limit (fails on held-out data, see `RESULTS.md`) |
| `access-requests` | time-boxed access grants: approval threshold below a human rejection, explicit deny |
| `support-triage--llm-grok` | `support-triage` with the skill generaliser backed by a **live** xAI `grok-4.7` model |
| `refund-desk--github-issues` | refund-desk with its ticket tool backed by **real GitHub Issues** (private sandbox); tickets are checked by reading them back |
| `refund-desk--stripe-test` | refund-desk with its payout tool backed by **real Stripe test-mode refunds**; payouts are checked by reading them back |
| `reporting--thin-limit-allowed` | comparison run under the old adoption rule (a 6-sample mined limit is adopted, and fails on held-out data) |
| `reporting--fault-whole-revert` | a harmful change is injected; the regression reverts the whole cycle (default) |
| `reporting--fault-attributed` | the same fault; per-change attribution reverts only the culprit |

Every run evaluates a **held-out** task set twice, under the starting configuration (`heldout-before`)
and under the adopted one (`heldout-after`). The cycle itself mines and reviews only its training run
(`c1-before`). The expected numbers for every run are in [`RESULTS.md`](RESULTS.md).

## A. In a browser (no install; works with this folder alone)

1. Open `<run>/bundle/explorer.html` from disk, adding the key pin to the address:

   ```text
   explorer.html#key=51ad6d3eccfae04958c0248edc60ac0a818b0584dc3878d6bfe4776d2ec8f81a
   ```

   It works offline. Ed25519 in WebCrypto needs a current browser: Chrome/Edge 137+, Firefox 129+ or
   Safari 17+.
2. The banner must read:

   ```text
   VERIFIED — N attestations, chain head sha256:… · N/N Ed25519 signatures valid, signer ed25519:0b6288c3f486c397
   ```

   N is the "Ledger entries" value in `RESULTS.md`.
3. With the pin, the banner shows **NOT VERIFIED** in any of these cases:
   - the bundle is unsigned;
   - it is signed by any other key;
   - any line, payload or signature was changed;
   - entries were dropped. The manifest signature covers the chain head and the entry count.
4. If your browser has no Ed25519, the banner says *signatures NOT checked*. Use a newer browser or
   option B.
5. To check the actual `ledger.jsonl` file rather than the copy embedded in the page, use
   *Re-verify another ledger.jsonl*.

The browser checks:
- the SHA-256 chain;
- the payload hashes;
- every attestation signature;
- the manifest signature;
- the key pin.

It does not replay policy or recompute metrics. That needs option B.

## B. Full verification in Python (no install)

`verify.py` sits next to this file. In the source repository it is
`examples/verified-runs/verify_standalone.py`. It is a single file using only the Python 3.10+
standard library, Ed25519 included. It does not import the SYNAPZ system: it re-implements every
check from the bundle format, so you can read it before running it.

```bash
python -I verify.py --all . --public-key 51ad6d3eccfae04958c0248edc60ac0a818b0584dc3878d6bfe4776d2ec8f81a
python -I verify.py <run>/bundle --public-key 51ad6d3eccfae04958c0248edc60ac0a818b0584dc3878d6bfe4776d2ec8f81a
```

The expected last line is `N bundle(s): ALL VERIFIED, no warnings`, where N is the number of bundle
folders, with exit code 0. Any failed
check, or any warning, makes the exit code 1. Leaving out `--public-key` prints a warning, so a run
without it never reports a clean pass.

In the source repository, the reference verifier gives the same verdicts:
`python -m synapz_frontier.improve.verify <run>/bundle --public-key …`, which needs
`pip install cryptography==50.0.0` for signatures. Before release, both verifiers were run against
each other:
- 96 random byte-level tampering attempts;
- six semantic forgeries fully re-signed with an attacker's key: an intern payout recorded as allowed,
  a removed review, inflated metrics, altered demonstration arguments, a held-out leak, and a remapped
  tool capability;
- Ed25519 checks against the RFC 8032 test vectors and OpenSSL.

They agreed in every case. Every forgery is rejected even without the pin, by a policy, metric,
skill or held-out check.

Each `PASS` line is one independent check:

| Check | What it proves |
|---|---|
| `file:*`, `ledger_chain`, `memory_chain`, `ledger_head`, `memory_head` | Every ledger and memory entry re-hashes and links to the one before it, with sequence numbers 0..N-1 and no gaps. The heads and entry counts match the manifest. |
| `payloads` | Every request and result payload the ledger references is present (`0 missing`) and re-hashes to its address. Each request payload also re-hashes to its attestation's `request_hash`. |
| `signing_key_pinned` | The bundle names the expected public key. |
| `manifest_signature` | The manifest statement is signed by that key. The statement covers the chain heads, entry counts, file hashes, the policy digests and the tool→capability map. This check catches truncation. |
| `attestation_signatures` | Every attestation, with no exceptions, carries a valid signature by that key over its digest. This catches a ledger that was rewritten and re-chained. |
| `initial_policy`, `policy_chain` | Replaying every approved policy review from the starting policy reproduces each recorded version and the final digest. No hard rule was touched. This covers attribution trials and reverts too. |
| `policy_conformance` | Every call recorded as allowed is still allowed under the policy version in force at that moment. Nothing bypassed policy. |
| `skill:<id>` | The adopted skill hashes to the digest the reviewer approved, and each demonstration is a real, successful, attested call by the human expert. |
| `metrics_recomputed` | Every before/after metric in the ledger equals the metrics recomputed from the calls that precede it. That includes interventions and escalation correctness (correct, missed, correct autonomous, unnecessary), recomputed from each attested task check's stated `needs_human` and the human involvement actually recorded. |
| `heldout_isolation` | No proposal evidence or skill demonstration comes from any held-out run (`heldout-*` and `heldout-indep-*`). Every `*-before` held-out run was measured before the first adopted change, and every `*-after` run started after the last one. |
| `facts` | Every memory fact, including the cycle verdict and the attribution record, re-verifies against the ledger. |

## C. Tamper test

Copy a bundle, change anything, and run A or B again. The result must be NOT VERIFIED. Things to try:
- flip a `"policy_decision"` value;
- edit a digit in a payload;
- delete the last ledger line and fix up the manifest;
- remove the `signing` block.

For each bundle, `RESULTS.md` section 9 lists four such attacks and the check that rejected each one.
The hardest is the `rechain` attack: an attestation is rewritten and the entire hash chain rebuilt.
Only the signatures catch it.

## What this does and does not establish

**Established:**
- each bundle was produced by the holder of the private key above and has not been altered since;
- it is internally consistent and policy-conformant;
- the held-out tasks did not inform the changes.

**Not established:**
- that the mock tools behave like production systems. These are deterministic in-process worlds
  with scripted humans;
- that a recorded LLM call really reached the provider. The xAI response ids are signed by the
  publisher, not by xAI;
- anything beyond the stated scope. See the Limitations section of [`RESULTS.md`](RESULTS.md).
