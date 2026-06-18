---
title: "pig issue3: Department Tree Import Without Permission Check"
description: "pig has a missing authorization vulnerability in `POST /dept/import`. An authenticated user can create unauthorized department nodes under sensitive parent departments, corrupting organization structure and any logic depending on department hierarchy"
tags:
  - pig
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

pig has a missing authorization vulnerability in `POST /dept/import`. An authenticated user can create unauthorized department nodes under sensitive parent departments, corrupting organization structure and any logic depending on department hierarchy

- Attack precondition: Any authenticated user
- Affected endpoint: ``POST /dept/import``
- Affected authorization property: `@HasPermission, parentName, sys_dept.parent_id, SysDept, parentId, sys_dept_add`
- Security impact: An authenticated user can create unauthorized department nodes under sensitive parent departments, corrupting organization structure and any logic depending on department hierarchy

### 1.2 Exploit path

1. Any authenticated user calls `POST /dept/import`. 2. The uploaded Excel row contains a chosen `parentName`. 3. Service resolves that parent department and writes a new `SysDept` with `parentId` set to that department ID. 4. The department hierarchy is modified without department-management authorization

### 1.3 Key code evidence

1. `SysDeptController.java`

Evidence location: SysDeptController.java
2. `SysDeptServiceImpl.java`

Evidence location: SysDeptServiceImpl.java

## 2. Existing checks and why they fail

- The service validates whether the parent department name exists. - It does not validate whether the current user can create a department under that parent. - It does not reuse the authorization requirement of the normal create endpoint

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add `@HasPermission("sys_dept_add")` to `POST /dept/import`. - Validate that the importer can create children under the resolved parent department. - Reuse the normal department creation service for imported rows

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/pig/issue3.html
