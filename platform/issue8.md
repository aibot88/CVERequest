---
title: "platform issue8: Role Authorization Model Readable Without Authorization"
description: "platform has a missing authorization vulnerability in GET /roles/{id}/detail, GET /roles/{roleId}/users, GET /roles/{role_id}/permissions, GET /roles/{roleId}/role_res. Leaks role data scope, role members, and role-resource authorization bindings"
tags:
  - platform
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

platform has a missing authorization vulnerability in GET /roles/{id}/detail, GET /roles/{roleId}/users, GET /roles/{role_id}/permissions, GET /roles/{roleId}/role_res. Leaks role data scope, role members, and role-resource authorization bindings

- Attack precondition: The attacker is authenticated and knows or can enumerate `roleId`
- Affected endpoint: `GET /roles/{id}/detail, GET /roles/{roleId}/users, GET /roles/{role_id}/permissions, GET /roles/{roleId}/role_res`
- Affected authorization property: `roleId, @SaCheckPermission`
- Security impact: Leaks role data scope, role members, and role-resource authorization bindings

### 1.2 Exploit path

Use `GET /roles/{id}/detail`, `GET /roles/{roleId}/users`, `GET /roles/{role_id}/permissions`, or `GET /roles/{roleId}/role_res`

### 1.3 Key code evidence

1. `RoleController.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/RoleController.java#L81
2. `RoleServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/RoleServiceImpl.java#L73
3. `UserRoleServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/UserRoleServiceImpl.java#L56
4. `RoleServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/RoleServiceImpl.java#L167

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add role read/detail permissions and filter readable roles by current-user manageability

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/platform/issue8.html
