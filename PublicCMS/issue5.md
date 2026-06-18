---
title: "PublicCMS issue5: Content Distribution Source / Target Authorization Bypass"
description: "PublicCMS has a missing authorization vulnerability in `POST /admin/cmsContent/distribute`. The attacker can copy content across authorization boundaries and create target content records with authorization-relevant `categoryId/userId/deptId` values"
tags:
  - PublicCMS
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

PublicCMS has a missing authorization vulnerability in `POST /admin/cmsContent/distribute`. The attacker can copy content across authorization boundaries and create target content records with authorization-relevant `categoryId/userId/deptId` values

- Attack precondition: The attacker is a logged-in backend administrator with content distribution permission and knows a source content ID plus target category IDs
- Affected endpoint: ``POST /admin/cmsContent/distribute``
- Affected authorization property: `cmsContent.userId, cmsContent.deptId, cmsContent.categoryId, id=<sourceContentId>, categoryIds=<targetCategoryIds>, distribute`
- Security impact: The attacker can copy content across authorization boundaries and create target content records with authorization-relevant `categoryId/userId/deptId` values

### 1.2 Exploit path

Submit `id=<sourceContentId>` and `categoryIds=<targetCategoryIds>` to copy content into target categories, without having permission over the source content or target categories

### 1.3 Key code evidence

1. `cmsContent.c`

Evidence location: cmsContent.c
2. `service.c`

Evidence location: service.c
3. `ControllerUtils.h`

Evidence location: ControllerUtils.h
4. `CmsContentAdminController.java`

Evidence location: CmsContentAdminController.java
5. `CmsContentService.java`

Evidence location: CmsContentService.java
6. `ControllerUtils.java`

Evidence location: ControllerUtils.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Require `hasContentPermissions(admin, source)` and validate every target category against the actor's department/category authorization before copying

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/PublicCMS/issue5.html
