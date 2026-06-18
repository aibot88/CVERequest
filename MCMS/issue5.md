---
title: "MCMS issue5: `/ms/cms/category/copyCategory`"
description: "MCMS has a missing authorization vulnerability in POST /ms/cms/category/list, POST /ms/cms/generate/list, GET /ms/cms/content/getFromFengMian, GET /ms/cms/content/copy, GET /ms/cms/category/copyCategory, GET /cms/category/get. An authenticated attacker can perform authorization-sensitive operations through POST /ms/cms/category/list, POST /ms/cms/generate/list, GET /ms/cms/content/getFromFengMian, GET /ms/cms/content/copy, GET /ms/cms/category/copyCategory, GET /cms/category/get without the required permission."
tags:
  - MCMS
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

MCMS has a missing authorization vulnerability in POST /ms/cms/category/list, POST /ms/cms/generate/list, GET /ms/cms/content/getFromFengMian, GET /ms/cms/content/copy, GET /ms/cms/category/copyCategory, GET /cms/category/get. An authenticated attacker can perform authorization-sensitive operations through POST /ms/cms/category/list, POST /ms/cms/generate/list, GET /ms/cms/content/getFromFengMian, GET /ms/cms/content/copy, GET /ms/cms/category/copyCategory, GET /cms/category/get without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `POST /ms/cms/category/list, POST /ms/cms/generate/list, GET /ms/cms/content/getFromFengMian, GET /ms/cms/content/copy, GET /ms/cms/category/copyCategory, GET /cms/category/get`
- Affected authorization property: `categoryDisplay, categoryIsSearch, mdiyModelId, categoryFlag, categoryParentIds, topId`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through POST /ms/cms/category/list, POST /ms/cms/generate/list, GET /ms/cms/content/getFromFengMian, GET /ms/cms/content/copy, GET /ms/cms/category/copyCategory, GET /cms/category/get without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to POST /ms/cms/category/list, POST /ms/cms/generate/list, GET /ms/cms/content/getFromFengMian, GET /ms/cms/content/copy, GET /ms/cms/category/copyCategory, GET /cms/category/get with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

No concrete source path was extracted automatically. Review the issue body and source tree before final CVE submission.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for POST /ms/cms/category/list, POST /ms/cms/generate/list, GET /ms/cms/content/getFromFengMian, GET /ms/cms/content/copy, GET /ms/cms/category/copyCategory, GET /cms/category/get before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/MCMS/issue5.html
