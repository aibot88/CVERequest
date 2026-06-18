---
title: "lilishop issue2: Missing Authorization in PUT /store/departmentRole/{victimDepartmentId}, /store/departmentRole*, departmentId/roleId, StoreDepartmentServiceImpl.update/deleteByIds, listByDepartmentId/updateByDepartmentId"
description: "lilishop has a missing authorization vulnerability in PUT /store/departmentRole/{victimDepartmentId}, /store/departmentRole*, departmentId/roleId, StoreDepartmentServiceImpl.update/deleteByIds, listByDepartmentId/updateByDepartmentId. An authenticated attacker can perform authorization-sensitive operations through PUT /store/departmentRole/{victimDepartmentId}, /store/departmentRole*, departmentId/roleId, StoreDepartmentServiceImpl.update/deleteByIds, listByDepartmentId/updateByDepartmentId without the required permission."
tags:
  - lilishop
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lilishop has a missing authorization vulnerability in PUT /store/departmentRole/{victimDepartmentId}, /store/departmentRole*, departmentId/roleId, StoreDepartmentServiceImpl.update/deleteByIds, listByDepartmentId/updateByDepartmentId. An authenticated attacker can perform authorization-sensitive operations through PUT /store/departmentRole/{victimDepartmentId}, /store/departmentRole*, departmentId/roleId, StoreDepartmentServiceImpl.update/deleteByIds, listByDepartmentId/updateByDepartmentId without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `PUT /store/departmentRole/{victimDepartmentId}, /store/departmentRole*, departmentId/roleId, StoreDepartmentServiceImpl.update/deleteByIds, listByDepartmentId/updateByDepartmentId`
- Affected authorization property: `StoreDepartmentRole, department_id, li_store_department.store_id, li_store_department_role, store_id, departmentId`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through PUT /store/departmentRole/{victimDepartmentId}, /store/departmentRole*, departmentId/roleId, StoreDepartmentServiceImpl.update/deleteByIds, listByDepartmentId/updateByDepartmentId without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to PUT /store/departmentRole/{victimDepartmentId}, /store/departmentRole*, departmentId/roleId, StoreDepartmentServiceImpl.update/deleteByIds, listByDepartmentId/updateByDepartmentId with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `StoreDepartmentRoleController.java`

Evidence location: StoreDepartmentRoleController.java
2. `StoreDepartmentRoleServiceImpl.java`

Evidence location: StoreDepartmentRoleServiceImpl.java
3. `StoreMenuMapper.java`

Evidence location: StoreMenuMapper.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for PUT /store/departmentRole/{victimDepartmentId}, /store/departmentRole*, departmentId/roleId, StoreDepartmentServiceImpl.update/deleteByIds, listByDepartmentId/updateByDepartmentId before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lilishop/issue2.html
