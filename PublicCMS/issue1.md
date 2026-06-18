---
title: "PublicCMS issue1: Role Authorization Grant Boundary Bypass"
description: "PublicCMS has a missing authorization vulnerability in `POST /admin/sysRole/save`. A lower-privileged backend administrator can create or modify a role to gain broader backend URL access, potentially all backend permissions"
tags:
  - PublicCMS
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

PublicCMS has a missing authorization vulnerability in `POST /admin/sysRole/save`. A lower-privileged backend administrator can create or modify a role to gain broader backend URL access, potentially all backend permissions

- Attack precondition: The attacker is a logged-in backend administrator with access to `sysRole/save`, but should not be allowed to grant permissions beyond their own role
- Affected endpoint: ``POST /admin/sysRole/save``
- Affected authorization property: `sysRole.ownsAllRight, sysRole.showAllModule, sysRoleModule.moduleId, sysRoleAuthorized.url, ownsAllRight=true, showAllModule=true`
- Security impact: A lower-privileged backend administrator can create or modify a role to gain broader backend URL access, potentially all backend permissions

### 1.2 Exploit path

Submit a role save request that sets `ownsAllRight=true`, `showAllModule=true`, or high-privilege `moduleIds`. The controller persists these values and regenerates role URL authorizations

### 1.3 Key code evidence

1. `SysRoleAdminController.java`

Evidence location: SysRoleAdminController.java
2. `SysRoleAuthorizedService.java`

Evidence location: SysRoleAuthorizedService.java
3. `AdminContextInterceptor.java`

Evidence location: AdminContextInterceptor.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Restrict `ownsAllRight/showAllModule` to full administrators only, and filter submitted `moduleIds` against the current administrator's own grantable module set before saving

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/PublicCMS/issue1.html
