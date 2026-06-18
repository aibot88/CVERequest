---
title: "PublicCMS issue4: Content Import Category Authorization Bypass"
description: "PublicCMS has a missing authorization vulnerability in `POST /admin/cmsContent/doImport`. The attacker can create or overwrite content in categories they should not be allowed to manage"
tags:
  - PublicCMS
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

PublicCMS has a missing authorization vulnerability in `POST /admin/cmsContent/doImport`. The attacker can create or overwrite content in categories they should not be allowed to manage

- Attack precondition: The attacker is a logged-in backend administrator with content import permission
- Affected endpoint: ``POST /admin/cmsContent/doImport``
- Affected authorization property: `cmsContent.categoryId, cmsContent.userId, cmsContent.deptId, categoryCode, siteId, userId`
- Security impact: The attacker can create or overwrite content in categories they should not be allowed to manage

### 1.2 Exploit path

Upload a content import package whose `categoryCode` points to a category outside the attacker's department/category permission scope

### 1.3 Key code evidence

1. `cmsContent.c`

Evidence location: cmsContent.c
2. `CmsContentAdminController.java`

Evidence location: CmsContentAdminController.java
3. `ContentExchangeComponent.java`

Evidence location: ContentExchangeComponent.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Reuse the same target-category authorization check from `cmsContent/save` for every imported content record before persisting it

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/PublicCMS/issue4.html
