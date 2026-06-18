---
title: "surveyking issue8: RBAC Grant Upper Bound Missing"
description: "surveyking has a missing authorization vulnerability in /api/system/user/update, /api/system/role/update, role.authority/userRole.roleId. An authenticated attacker can perform authorization-sensitive operations through /api/system/user/update, /api/system/role/update, role.authority/userRole.roleId without the required permission."
tags:
  - surveyking
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

surveyking has a missing authorization vulnerability in /api/system/user/update, /api/system/role/update, role.authority/userRole.roleId. An authenticated attacker can perform authorization-sensitive operations through /api/system/user/update, /api/system/role/update, role.authority/userRole.roleId without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `/api/system/user/update, /api/system/role/update, role.authority/userRole.roleId`
- Affected authorization property: `system:user:update, system:role:update, roles, authorities, userIds, role.authority`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through /api/system/user/update, /api/system/role/update, role.authority/userRole.roleId without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to /api/system/user/update, /api/system/role/update, role.authority/userRole.roleId with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `SystemApi.java`

Evidence location: SystemApi.java#L102
2. `SystemServiceImpl.java`

Evidence location: SystemServiceImpl.java#L95
3. `SystemServiceImpl.java`

Evidence location: SystemServiceImpl.java#L107
4. `UserServiceImpl.java`

Evidence location: UserServiceImpl.java#L267
5. `UserServiceImpl.java`

Evidence location: UserServiceImpl.java#L127
6. `role.authority/userRole.roleId`

Evidence location: role.authority/userRole.roleId

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for /api/system/user/update, /api/system/role/update, role.authority/userRole.roleId before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/surveyking/issue8.html
