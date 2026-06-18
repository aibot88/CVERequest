---
title: "mall4cloud issue2: Role Permission Edges Write Arbitrary `menu_id` / `menu_permission_id`"
description: "mall4cloud has a missing authorization vulnerability in POST /role, PUT /role, bizType/tenantId. A role manager can create or update a role to include unauthorized menu or API permission edges. Once assigned, those edges affect RBAC authorization decisions"
tags:
  - mall4cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall4cloud has a missing authorization vulnerability in POST /role, PUT /role, bizType/tenantId. A role manager can create or update a role to include unauthorized menu or API permission edges. Once assigned, those edges affect RBAC authorization decisions

- Attack precondition: Any authenticated user
- Affected endpoint: `POST /role, PUT /role, bizType/tenantId`
- Affected authorization property: ``role_menu.role_id`, `role_menu.menu_id`, `role_menu.menu_permission_id`, `menu.biz_type`, `menu_permission.biz_type``
- Security impact: A role manager can create or update a role to include unauthorized menu or API permission edges. Once assigned, those edges affect RBAC authorization decisions

### 1.2 Exploit path

The attacker sends crafted requests to POST /role, PUT /role, bizType/tenantId with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `RoleMenuMapper.xml`

Evidence location: RoleMenuMapper.xml
2. `MenuPermissionMapper.xml`

Evidence location: MenuPermissionMapper.xml

## 2. Existing checks and why they fail

- Target role ownership is checked on update, but the permission edges being attached to that role are not checked. - There is no role hierarchy or "current user can grant this permission" check. - There is no mapper-level join to constrain `menu_permission.biz_type` to the current `sysType`

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for POST /role, PUT /role, bizType/tenantId before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall4cloud/issue2.html
