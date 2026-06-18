---
title: "surveyking issue6: Repo Template Scope Authorization Bypass"
description: "surveyking has a missing authorization vulnerability in /api/repo/import, /api/repo/unbind, /api/repo/pick, /api/repo/export, repoId/id. An authenticated attacker can perform authorization-sensitive operations through /api/repo/import, /api/repo/unbind, /api/repo/pick, /api/repo/export, repoId/id without the required permission."
tags:
  - surveyking
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

surveyking has a missing authorization vulnerability in /api/repo/import, /api/repo/unbind, /api/repo/pick, /api/repo/export, repoId/id. An authenticated attacker can perform authorization-sensitive operations through /api/repo/import, /api/repo/unbind, /api/repo/pick, /api/repo/export, repoId/id without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `/api/repo/import, /api/repo/unbind, /api/repo/pick, /api/repo/export, repoId/id`
- Affected authorization property: `repo:create, batchCreate, Template.repoId, assertManagePermission, repoId`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through /api/repo/import, /api/repo/unbind, /api/repo/pick, /api/repo/export, repoId/id without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to /api/repo/import, /api/repo/unbind, /api/repo/pick, /api/repo/export, repoId/id with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `RepoApi.java`

Evidence location: RepoApi.java#L79
2. `RepoApi.java`

Evidence location: RepoApi.java#L155
3. `RepoServiceImpl.java`

Evidence location: RepoServiceImpl.java#L118
4. `RepoServiceImpl.java`

Evidence location: RepoServiceImpl.java#L177
5. `RepoServiceImpl.java`

Evidence location: RepoServiceImpl.java#L190
6. `RepoServiceImpl.java`

Evidence location: RepoServiceImpl.java#L361
7. `RepoPartnerServiceImpl.java`

Evidence location: RepoPartnerServiceImpl.java#L40

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for /api/repo/import, /api/repo/unbind, /api/repo/pick, /api/repo/export, repoId/id before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/surveyking/issue6.html
