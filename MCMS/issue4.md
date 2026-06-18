---
title: "MCMS issue4: Content copy uses `cms:content:save` to read and clone source content"
description: "MCMS has a missing authorization vulnerability: Content copy uses `cms:content:save` to read and clone source content. A save-only user can read and duplicate source article data they are not authorized to view"
tags:
  - MCMS
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

MCMS has a missing authorization vulnerability: Content copy uses `cms:content:save` to read and clone source content. A save-only user can read and duplicate source article data they are not authorized to view

- Attack precondition: The attacker is an authenticated backend `manager` user with `cms:content:save` but without `cms:content:view`, knows a source content id, and the source content belongs to a list-type category
- Security impact: A save-only user can read and duplicate source article data they are not authorized to view

### 1.2 Exploit path

Request `GET /ms/cms/content/copy?id=<sourceId>`. The endpoint reads the source content, resets a few fields, saves it as a new content record, and returns the cloned entity

### 1.3 Key code evidence

1. `src/main/java/net/mingsoft/cms/action/ContentAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/ContentAction.java#L271
2. `src/main/java/net/mingsoft/cms/action/ContentAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/ContentAction.java#L278
3. `src/main/java/net/mingsoft/cms/action/ContentAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/ContentAction.java#L305
4. `src/main/java/net/mingsoft/cms/action/ContentAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/ContentAction.java#L306

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Require `cms:content:view` or equivalent source-content read authorization before copying. Return only the new id if full entity response is not needed

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/MCMS/issue4.html
