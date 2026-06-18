---
title: "platform issue10: Role User Assignment Lacks Target Role and User Scope Checks"
description: "platform has a missing authorization vulnerability in PUT /roles/{roleId}/assign-users. Adds users to high-privilege, built-in, or super roles, causing privilege escalation after permission refresh or re-login"
tags:
  - platform
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

platform has a missing authorization vulnerability in PUT /roles/{roleId}/assign-users. Adds users to high-privilege, built-in, or super roles, causing privilege escalation after permission refresh or re-login

- Attack precondition: The attacker has `sys:role:assign-users`
- Affected endpoint: `PUT /roles/{roleId}/assign-users`
- Affected authorization property: `sys:role:assign-users, assignUser, readonly, superRole, sys_user_role`
- Security impact: Adds users to high-privilege, built-in, or super roles, causing privilege escalation after permission refresh or re-login

### 1.2 Exploit path

Use `PUT /roles/{roleId}/assign-users` to add arbitrary users to arbitrary roles

### 1.3 Key code evidence

1. `RoleController.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/RoleController.java#L138
2. `RoleServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/RoleServiceImpl.java#L137
3. `RoleServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/RoleServiceImpl.java#L121

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Block assignment of protected roles, validate target users by data scope, and enforce a grantable-role hierarchy

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/platform/issue10.html
