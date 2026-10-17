---
id: "0001"
title: "upgrade example-web to 2.4"
date: "2026-10-17"
status: "done"
requester: "demo"
go: "chat, 2026-10-17"
risk: "low"
items:
  - "example-web"
links: []
evidence:
  - "healthz returned version 2.4.0; no errors in logs since restart"
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
