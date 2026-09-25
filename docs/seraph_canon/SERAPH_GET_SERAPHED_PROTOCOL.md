# SiteShield Get Seraphed Protocol Bridge

**Status rule:** Active for SiteShield only when present on the live default branch; otherwise repository-local candidate.  
**Classification:** SiteShield Repository Continuity / Seraph Canon Bridge  
**Repository:** `SeraphPLC/siteshield`  
**Created:** 2026-09-24

## Purpose

This file gives SiteShield a repository-local `Get Seraphed` entry point without copying private or fast-changing Seraph Core state into the public website repository.

The shared Seraph Get Seraphed canon remains authoritative for Seraph-wide continuity when an authorized observer can reach it. This file narrows that canon to SiteShield's public repository truth and never weakens its evidence, authority, privacy, or mutation gates.

## Canonical Phrase

```text
Get Seraphed.
```

For SiteShield this means:

> Ground the current SiteShield repository and task from live evidence, recover the applicable Seraph continuity rules when authorized and reachable, preserve public/private boundaries, discover the strongest admissible AI/provider routes when a council is requested, and do not mutate or deploy until the applicable gates are satisfied.

## Required SiteShield Grounding

Confirm:

- repository identity;
- live default branch and exact head SHA;
- current README and public product description;
- deployment/configuration surfaces relevant to the task, including `vercel.json`, `_headers`, static pages, and other changed paths when applicable;
- open branches/PRs and changed-path overlap relevant to the requested work;
- whether the task is public-site content, security methodology, deployment configuration, purchase flow, continuity test, or another SiteShield lane;
- what can actually be read, executed, modified, or deployed from the current observer.

Do not treat a stale chat, local copy, old deployment, or another repository as proof of current SiteShield state.

## Seraph Core Bridge

When the authorized observer can reach the current Seraph Core Get Seraphed canon:

1. read the live canonical protocol rather than relying on a copied snapshot;
2. apply its grounding, evidence, provider/model, AI Council, coordination, and mutation rules;
3. then apply this SiteShield-local overlay.

When Core is unavailable:

- report the external-canon gap;
- preserve the local rules in this file;
- do not invent internal Seraph state or authority;
- do not downgrade the missing canon to an assumed PASS.

This public repository must not contain customer secrets, private credentials, internal tokens, private-key material, or private Seraph evidence merely to make continuity easier.

## Advanced AI Council and Provider Discovery

If Michael asks for an AI Council, Advanced AI Council, independent model review, or named provider participation:

- discover the strongest task-appropriate routes actually reachable in the current environment before selecting seats;
- explicitly consider OpenAI/ChatGPT, Anthropic/Claude, xAI/Grok, Google/Gemini, GitHub Copilot, and qualified local models as candidate families without assuming any is available;
- do not default to a small local-only council merely because it is easiest when stronger qualified external routes are actually reachable;
- before declaring a requested provider unavailable, perform bounded task-scoped route discovery;
- never silently substitute one provider/model for another;
- count a seat as participating only after a real request is dispatched through the named route and a response/receipt is returned;
- preserve provider/model independence groups;
- preserve spend, credential, disclosure, execution-authority, tool, and no-blind-retry gates;
- treat model consensus as advisory; repository evidence, primary sources, measurements, tests, and deployment readback outrank council agreement.

Minimum invariants:

```text
ROUTE_DISCOVERED != ROUTE_QUALIFIED
ROUTE_QUALIFIED != ROUTE_EXECUTED
REQUEST_DISPATCHED != RESPONSE_RECEIVED
RESPONSE_RECEIVED != CLAIM_VERIFIED
PROVIDER_LABEL != EXECUTION_PROVENANCE
LOCAL_AVAILABLE != BEST_AVAILABLE
COUNCIL_CONSENSUS != SOURCE_EVIDENCE
```

## Artifact Nomenclature Bridge

When SiteShield work creates, exports, packages, downloads, or names a Seraph-owned durable artifact, resolve the live Core standard:

`docs/canon/SERAPH_ARTIFACT_NOMENCLATURE_STANDARD_R1_2026268T202000Z.md`

Use UTC ordinal/Julian-day-of-year timestamps in `YYYYDDDTHHMMSSZ` form. Provider-required fixed names are interface aliases only; the Seraph archival/export name must remain meaningful and timestamped.

## Mutation Boundary

`Get Seraphed` authorizes grounding, not unrestricted mutation.

For repository changes:

- search before creating;
- use an isolated branch when appropriate;
- re-read overlapping PR/branch state immediately before mutation;
- preserve first failure and do not blindly retry ambiguous writes;
- never infer permission to merge, deploy, publish, change payment configuration, alter credentials, or modify production merely from a grounding request.

If Michael's request separately authorizes bounded repository work, ground first and continue within that scope.

## Completion

A SiteShield observer may report `SERAPHED` only when the task-scoped repository state and applicable continuity sources were actually reconstructed.

Use `PARTIALLY SERAPHED` or `BLOCKED` when a material Core, provider, deployment, credential, or local-runtime dependency is unavailable.

A compact successful receipt should include the SiteShield head SHA, the task scope, any material capability/provider gaps, and the mutation boundary.

## Public/Private Boundary

This repository is the public SiteShield website surface. It is not evidence of:

- private Seraph runtime state;
- AI provider credentials or entitlement;
- customer data;
- live deployment health unless separately read back;
- current model/provider qualification;
- internal commercial or financial authority.

Those claims require their own current evidence from the appropriate authorized systems.
