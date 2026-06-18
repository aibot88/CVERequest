---
title: "xwiki issue1: Confirmed Vulnerability"
description: "xwiki has a missing authorization vulnerability: Confirmed Vulnerability. unauthorized access to authorization-sensitive state"
tags:
  - xwiki
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

xwiki has a missing authorization vulnerability: Confirmed Vulnerability. unauthorized access to authorization-sensitive state


### 1.3 Key code evidence

1. `XWikiAnnotationRightService.c`

Evidence location: XWikiAnnotationRightService.c
2. `services.refactoring.c`

Evidence location: services.refactoring.c

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/xwiki/issue1.html
