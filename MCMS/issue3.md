---
title: "MCMS issue3: `getFromFengMian` bypasses `cms:content:view`"
description: "MCMS has a missing authorization vulnerability in GET /ms/cms/content/getFromFengMian?categoryId=..., GET /ms/cms/content/getFromFengMian?categoryId=, /getFromFengMian. Unauthorized users can read article fields including category relation, display status, type, details, out-link, and hit count"
tags:
  - MCMS
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

MCMS has a missing authorization vulnerability in GET /ms/cms/content/getFromFengMian?categoryId=..., GET /ms/cms/content/getFromFengMian?categoryId=, /getFromFengMian. Unauthorized users can read article fields including category relation, display status, type, details, out-link, and hit count

- Attack precondition: The attacker is an authenticated backend `manager` user without `cms:content:view`, and knows or can guess a `categoryId`
- Affected endpoint: `GET /ms/cms/content/getFromFengMian?categoryId=..., GET /ms/cms/content/getFromFengMian?categoryId=, /getFromFengMian`
- Affected authorization property: `manager, cms:content:view, categoryId, ContentEntity, @RequiresPermissions, ContentEntity::getCategoryId`
- Security impact: Unauthorized users can read article fields including category relation, display status, type, details, out-link, and hit count

### 1.2 Exploit path

Request `GET /ms/cms/content/getFromFengMian?categoryId=...`. The endpoint validates only that `categoryId` is non-empty, queries content by category, and returns the first `ContentEntity`

### 1.3 Key code evidence

1. `src/main/java/net/mingsoft/cms/action/ContentAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/ContentAction.java#L165
2. `src/main/java/net/mingsoft/cms/action/ContentAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/ContentAction.java#L171
3. `src/main/java/net/mingsoft/cms/action/ContentAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/ContentAction.java#L175
4. `src/main/java/net/mingsoft/cms/action/ContentAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/ContentAction.java#L123

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add `@RequiresPermissions("cms:content:view")` and apply category/content visibility or scope checks before returning data

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/MCMS/issue3.html
