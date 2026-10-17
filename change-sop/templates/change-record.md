---
id: "0000"
title: "<short, specific title>"
date: "<YYYY-MM-DD>"
status: "proposed"            # proposed | approved | done | rolled-back
requester: "<who asked for this>"
go: "<how/when the GO was given, e.g. 'chat, 2026-10-17 14:02' or a plan id>"
risk: "low"                   # low | medium | high
items:
  - "<the thing(s) this change touches, one per line>"
links:
  - "<ticket, PR, plan id, monitoring dashboard — whatever is relevant>"
evidence:
  - "<what was checked afterwards, and what it showed — fill in during step 6>"
---

## Context

<What state is this starting from, and why is the change needed? One or two paragraphs — link to the reference
doc rather than repeating it.>

## What was done

<The actual steps run, in order, with real commands/output where it matters. Not the plan — what actually
happened, including anything that deviated from the plan and why.>

## Verifications

<The evidence: the real check you ran and what it returned. "Looked fine" is not a verification — the actual
version string, HTTP status, row count, or external test belongs here.>

## Rollback

<The exact steps to undo this change, even if it was never needed. If a snapshot or backup was taken, its name
goes here.>
