---
title: "MCMS issue2: Generate module category list bypasses category/generate read permission"
description: "MCMS has a missing authorization vulnerability: Generate module category list bypasses category/generate read permission. Unauthorized backend users can retrieve complete category metadata through the static-generation helper endpoint"
tags:
  - MCMS
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

MCMS has a missing authorization vulnerability: Generate module category list bypasses category/generate read permission. Unauthorized backend users can retrieve complete category metadata through the static-generation helper endpoint

- Attack precondition: The attacker is an authenticated backend `manager` user without category-view or generate-view privileges
- Security impact: Unauthorized backend users can retrieve complete category metadata through the static-generation helper endpoint

### 1.2 Exploit path

Request `GET/POST /ms/cms/generate/list`. The endpoint has no method-level permission and returns `categoryBiz.list(...)`

### 1.3 Key code evidence

1. `src/main/java/net/mingsoft/cms/action/GeneraterAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/GeneraterAction.java#L131
2. `src/main/java/net/mingsoft/cms/action/GeneraterAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/GeneraterAction.java#L134
3. `src/main/java/net/mingsoft/cms/action/GeneraterAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/GeneraterAction.java#L146

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add `@RequiresPermissions("cms:category:view")` or a dedicated generate read permission such as `cms:generate:view`

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/MCMS/issue2.html
