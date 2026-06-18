---
title: "xwiki issue1: Confirmed Vulnerability"
description: "xwiki has a missing authorization vulnerability. An authenticated attacker can perform authorization-sensitive operations without the required permission."
tags:
  - xwiki
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

xwiki has a missing authorization vulnerability. An authenticated attacker can perform authorization-sensitive operations without the required permission.

- Attack precondition: Any authenticated user
- Affected authorization property: `role, access_level, member, author, RequiredRightClass.level, XWikiRights.*`
- Security impact: An authenticated attacker can perform authorization-sensitive operations without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to the affected endpoint with target identifiers or authorization-sensitive fields that should be rejected.

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

## 4. Recommended fix

Enforce server-side authorization for the vulnerable operation before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/xwiki/issue1.html
