---
title: "pig issue2: Role-Menu Permission Binding Write Without Grant Boundary"
description: "pig has a missing authorization vulnerability in `PUT /role/menu`. The attacker can grant excessive permissions to roles, including their own role, resulting in privilege escalation and persistent RBAC model corruption"
tags:
  - pig
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

pig has a missing authorization vulnerability in `PUT /role/menu`. The attacker can grant excessive permissions to roles, including their own role, resulting in privilege escalation and persistent RBAC model corruption

- Affected endpoint: ``PUT /role/menu``
- Security impact: The attacker can grant excessive permissions to roles, including their own role, resulting in privilege escalation and persistent RBAC model corruption

### 1.2 Exploit path

1. Attacker has `sys_role_perm` but should not have global superadmin capability. 2. Attacker submits a target `roleId`, potentially their own role. 3. Attacker supplies high-privilege `menuIds`, such as user management or role management permissions. 4. Service deletes the role's old menu bindings and saves the attacker-provided bindings. 5. Users with that role receive the newly granted permissions after cache refresh/re-login

### 1.3 Key code evidence

1. `SysRoleController.java`

Evidence location: SysRoleController.java
2. `SysRoleMenuServiceImpl.java`

Evidence location: SysRoleMenuServiceImpl.java
3. `SysUserServiceImpl.java`

Evidence location: SysUserServiceImpl.java

## 2. Existing checks and why they fail

- `sys_role_perm` protects the operation but does not define or enforce an authorization upper bound.
- No code checks target role level, target role ownership, self-modification, or whether every requested `menuId` is grantable by the current user.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce role hierarchy and grantable-menu constraints. - Forbid modifying the current user's own role unless the operator is a true superadmin. - Require every requested `menuId` to be within the current user's grantable permission closure. - Add audit logs specifically for role permission changes

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/pig/issue2.html
