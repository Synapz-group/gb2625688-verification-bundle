# SYNAPZ Governed Self-Improvement — Verifiable Evidence Bundles

[![Verify bundles](https://github.com/Synapz-group/gb2625688-verification-bundle/actions/workflows/verify.yml/badge.svg)](https://github.com/Synapz-group/gb2625688-verification-bundle/actions/workflows/verify.yml)

**Patent:** GB2625688.3 (filed 28 October 2026)
**Status:** Patent pending

This repository contains complete, Ed25519-signed evidence bundles exported from the SYNAPZ governed
closed-loop self-improvement system. Anyone can re-verify them offline, with no access to the live
system and no trust in us.

## What this is

Each bundle records one governed improvement cycle on a small software workflow:

1. The agent runs a suite of tasks.
2. The system mines its own audit log for proposals: learned skills and policy changes.
3. Each proposal is back-tested and goes through an attested review.
4. Adopted changes are re-tested, and rolled back automatically if anything regresses.

Every tool call, approval, review and metric is an attestation in a hash-chained ledger, and every
attestation is signed. Each bundle is **complete**: there are no sequence gaps, and every payload the
ledger references is present.

## Real vs mock — read this first

| Bundle | Real external system | Mock (in-process) |
|---|---|---|
| `refund-desk`, `support-triage`, `data-validation`, `reporting`, `access-requests` | none | every tool; scripted human approver and expert |
| `refund-desk--github-issues` | **GitHub Issues**: every ticket is a real issue in a private sandbox repository, and is checked by reading it back from GitHub | payouts, FX quotes; scripted human approver and expert |
| `refund-desk--stripe-test` | **Stripe (test mode)**: every payout is a real test-mode refund, checked by reading it back from Stripe. No real money moves | tickets, FX quotes; scripted human approver and expert |
| `support-triage--llm-grok` | **xAI `grok-4.7`**, the live model used as the skill generaliser | every tool; scripted humans |
| `reporting--thin-limit-allowed`, `reporting--fault-whole-revert`, `reporting--fault-attributed` | none | every tool; scripted humans |

The independent held-out task sets (below) were also written by `grok-4.7`.

## What is included

- **Bundles**, each `<run>/bundle/` with its ledger, payloads, memory log, starting policy, signed
  manifest and `explorer.html`:
  - five workflows;
  - one run with a real external ticket system (GitHub Issues);
  - one run with a real external payment API in test mode (Stripe);
  - one live-LLM run;
  - a comparison run under the old adoption rule;
  - two fault-injection runs: whole-cycle rollback vs per-change attribution.
- **`verify.py`**, a standalone verifier: one file, Python 3.10+ standard library only, Ed25519 included.
  It does not import the SYNAPZ system.
- **`VERIFY-ALL.md`**: step-by-step verification, in Python or in a browser.
- **`RESULTS.md`**: every number, per run and per task set, plus the tamper tests and the limitations.

## How to verify

```bash
git clone https://github.com/Synapz-group/gb2625688-verification-bundle && cd gb2625688-verification-bundle
python -I verify.py --all . --public-key 51ad6d3eccfae04958c0248edc60ac0a818b0584dc3878d6bfe4776d2ec8f81a
```

Expected result: `N bundle(s): ALL VERIFIED, no warnings`, with exit code 0. Signer
`ed25519:0b6288c3f486c397`, public key `51ad6d3eccfae04958c0248edc60ac0a818b0584dc3878d6bfe4776d2ec8f81a`.
You can also open `<run>/bundle/explorer.html#key=<public key>` in a browser.

## What the bundles show

**Two signals, not one.** Besides *interventions* (escalations to a human expert plus human approvals),
every task is judged against a fixed, stated escalation rule per workflow, for example "refund payouts
above 500 need a human". That gives two counts:
- **correct escalations:** a human was needed, and one was involved;
- **missed escalations:** a human was needed, and none was involved. This is the dangerous direction.

The counts are recorded in the signed ledger and recomputed by the verifier. Across every run and every
task set below, **missed escalations = 0**.

- **Training tasks.** Interventions fall to 0 in all five workflows (12, 6, 9, 6 and 6 → 0), with every
  task still passing. Every probe of a forbidden action stays blocked.
- **Held-out tasks we wrote.** These are never mined or reviewed, and the verifier checks that isolation.
  - The gains hold in all five workflows.
  - Where the stated rule requires a human, the system still escalates: refund-desk, data-validation and
    reporting each have 1/1 correct escalations.
  - Hard rules keep blocking unseen violations.
- **Held-out tasks written independently.** For refund-desk, support-triage and data-validation, `grok-4.7`
  wrote a third task set. It saw only a schema card, never our tasks.
  - The gains hold, all tasks pass and every probe is blocked.
  - Correct escalations: refund-desk 2/2, data-validation 1/1.
  - Two requests sat between the learned threshold and the stated rule (a payout of 499.99 and a release
    of 49,999 rows). Each still went to a human: a conservative, unnecessary escalation, not a missed one.
- **A stricter adoption rule.** In an earlier version, `reporting` adopted a spending limit mined from
  only 6 calls, and it blocked a legitimate unseen report.
  - Mined numeric limits now need at least 10 supporting observations.
  - The 6-sample limit is rejected, and the held-out regression no longer occurs (6/6 passed).
  - The old behaviour is kept as a comparison bundle, `reporting--thin-limit-allowed`, where held-out
    tasks fall from 6/6 to 5/6 passed.
- **A real external ticket system.** In `refund-desk--github-issues`, the ticket tool opens real GitHub
  issues in a private sandbox repository.
  - The calls still go through the same policy gates, attestation and signatures, and any API error
    fails the call.
  - The evaluator checks every ticket by reading the issue back from GitHub.
  - The run created 20 real issues. Its results match the mock run: interventions 12 → 0 on training;
    17/17, 10/10 and 12/12 passed on training and both held-out sets; 0 missed escalations.
  - The issue URLs and node ids are in the signed record. The sandbox repository is private, so public
    readers can check the agent's side of every call but not the issues themselves.
- **A real external payment API (test mode).** In `refund-desk--stripe-test`, every payout is a real Stripe
  test-mode refund: a test charge for the original order, then a refund of exactly the payout amount.
  - The policy gates run before Stripe is called, including the 5,000 hard limit, human approval and the
    intern deny. Blocked requests never reach Stripe.
  - The client accepts only test-mode keys, refuses any live-mode object, and makes every request
    idempotent.
  - The evaluator checks each payout by reading the refund and its payment back from Stripe.
  - The run made 34 test-mode refunds, all succeeded. Its results match the mock run: interventions 12 → 0
    on training; 17/17, 10/10 and 12/12 passed; 0 missed escalations.
  - A first attempt failed every payout check because of a bug in our read-back check, not in Stripe. It
    was discarded and is documented in `RESULTS.md`.
- **Live LLM.** With `grok-4.7` as the skill generaliser:
  - the learned skill was adopted only after it reproduced every recorded expert escalation exactly;
  - escalations went to 0 on training and on both held-out sets;
  - every model call is in the signed record.
- **Per-change rollback.** A deliberately harmful change was injected and rubber-stamped.
  - Whole-cycle rollback undoes everything, including the good changes.
  - Per-change attribution pins the regression on the injected change and reverts only that.
- **Tamper evidence.** Every bundle was attacked four ways, and both verifiers rejected every attack:
  - a flipped decision;
  - a rewritten record with the whole hash chain rebuilt;
  - a truncated ledger with the manifest fixed up;
  - stripped signatures.

## What these bundles do **not** demonstrate

- **Real-world systems or production data.** Apart from three components, every tool is an in-process
  mock and the humans are scripted. The three real components are:
  - the ticket tool in `refund-desk--github-issues` (GitHub Issues, private sandbox);
  - the payout tool in `refund-desk--stripe-test` (Stripe **test mode**, so no real money moves);
  - the LLM in `support-triage--llm-grok`.
  Each real component is used in its own run only.
- **Generalisation beyond our task shapes.** Both held-out sets reuse our task shapes and stated rules. The
  independent set had a different author, but it is still not an external benchmark.
- **Pre-registration.** The escalation rules were set by us after the earlier runs. They are never learned
  or tuned, but they were not fixed in advance.
- **That model calls reached the provider.** Response ids are signed by us, not by xAI.
- **Key custody beyond a single software key.** There is no HSM, key rotation or transparency log yet.
  Trust the public key above only through channels we control.
- **Commercial deployment or customer use.**

Full limitations are in `RESULTS.md`.

## Earlier release

An earlier version of this repository published abridged bundles with sequence gaps and missing
payloads. Those bundles could not be completed and have been withdrawn. This release replaces them
entirely; none of its numbers come from the earlier version.

## License

Evidence bundles and documentation: CC0 (public domain), for verification purposes.
The underlying system remains proprietary.

## Contact

SYNAPZ — https://x.com/synapz_group
