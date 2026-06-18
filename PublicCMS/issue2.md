---
title: "PublicCMS issue2: Backend User Superuser / Role Assignment Bypass"
description: "PublicCMS has a missing authorization vulnerability in `POST /admin/sysUser/save`. The attacker can create or upgrade a backend user with roles they should not be able to grant, enabling privilege escalation in the admin console"
tags:
  - PublicCMS
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

PublicCMS has a missing authorization vulnerability in `POST /admin/sysUser/save`. The attacker can create or upgrade a backend user with roles they should not be able to grant, enabling privilege escalation in the admin console

- Attack precondition: The attacker is a logged-in backend administrator with access to user creation or user editing
- Affected endpoint: ``POST /admin/sysUser/save``
- Affected authorization property: `sysUser.superuser, sysUser.roles, sysRoleUser.roleId, superuser=true, roleIds, superuser`
- Security impact: The attacker can create or upgrade a backend user with roles they should not be able to grant, enabling privilege escalation in the admin console

### 1.2 Exploit path

Submit `superuser=true` and arbitrary high-privilege `roleIds` while creating or updating a user

### 1.3 Key code evidence

1. `SysUserAdminController.java`

Evidence location: SysUserAdminController.java
2. `SysRoleUserService.java`

Evidence location: SysRoleUserService.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Only full administrators may set `superuser`. Validate every submitted `roleId` against a current-admin grantable-role set and same-site role ownership before saving

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/PublicCMS/issue2.html
