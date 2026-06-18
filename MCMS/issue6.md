---
title: "MCMS issue6: Public category get bypasses public visibility filters"
description: "MCMS has a missing authorization vulnerability in GET /cms/category/get?id=..., GET /cms/category/get?id=, /cms/category/get, /ms/**. Public users can retrieve hidden or non-CMS category metadata that the public category list intentionally filters out"
tags:
  - MCMS
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

MCMS has a missing authorization vulnerability in GET /cms/category/get?id=..., GET /cms/category/get?id=, /cms/category/get, /ms/**. Public users can retrieve hidden or non-CMS category metadata that the public category list intentionally filters out

- Attack precondition: Unauthenticated public user knows or guesses a category id
- Affected endpoint: `GET /cms/category/get?id=..., GET /cms/category/get?id=, /cms/category/get, /ms/**`
- Affected authorization property: `categoryBiz.getById(...), CategoryEntity, category_display = 'enable', is_child = 'cms', categoryBiz.getById(category.getId()), cms_category.category_display = 'enable'`
- Security impact: Public users can retrieve hidden or non-CMS category metadata that the public category list intentionally filters out

### 1.2 Exploit path

Request `GET /cms/category/get?id=...`. The public endpoint directly calls `categoryBiz.getById(...)` and returns the full `CategoryEntity`

### 1.3 Key code evidence

1. `src/main/java/net/mingsoft/cms/action/web/CategoryAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/web/CategoryAction.java#L108
2. `src/main/java/net/mingsoft/cms/action/web/CategoryAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/web/CategoryAction.java#L115
3. `src/main/java/net/mingsoft/cms/action/web/CategoryAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/web/CategoryAction.java#L116
4. `src/main/java/net/mingsoft/cms/biz/impl/CategoryBizImpl.java`

Evidence location: src/main/java/net/mingsoft/cms/biz/impl/CategoryBizImpl.java#L369
5. `doc/mcms-6.2.0.sql`

Evidence location: doc/mcms-6.2.0.sql#L439
6. `cms_category.c`

Evidence location: cms_category.c

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add `categoryDisplay=enable`, `isChild=cms`, deletion, and site-scope filters to public get. Return a public DTO instead of raw `CategoryEntity`

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/MCMS/issue6.html
