---
title: "yudao-cloud issue1: System Permission Assignment Lacks Grant-Bound Checks"
description: "yudao-cloud has a missing authorization vulnerability in system_role.data_scope/data_scope_dept_ids. A lower-privileged administrator can grant roles, menus, or data scopes beyond their own authority. This can modify `system_user_role.role_id`, `system_role_menu.menu_id`, and `system_role.data_scope/data_scope_dept_ids`, which are directly consumed by later RBAC and data permission decisions"
tags:
  - yudao-cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

yudao-cloud has a missing authorization vulnerability in system_role.data_scope/data_scope_dept_ids. A lower-privileged administrator can grant roles, menus, or data scopes beyond their own authority. This can modify `system_user_role.role_id`, `system_role_menu.menu_id`, and `system_role.data_scope/data_scope_dept_ids`, which are directly consumed by later RBAC and data permission decisions

- Attack precondition: Attacker has one or more function permissions such as `system:permission:assign-role-menu`, `system:permission:assign-role-data-scope`, or `system:permission:assign-user-role`, but should not be allowed to grant higher roles, menus, or data scopes
- Affected endpoint: `system_role.data_scope/data_scope_dept_ids`
- Affected authorization property: `system:permission:assign-role-menu, system:permission:assign-role-data-scope, system:permission:assign-user-role, roleId, menuIds, roleIds`
- Security impact: A lower-privileged administrator can grant roles, menus, or data scopes beyond their own authority. This can modify `system_user_role.role_id`, `system_role_menu.menu_id`, and `system_role.data_scope/data_scope_dept_ids`, which are directly consumed by later RBAC and data permission decisions

### 1.2 Exploit path

The attacker calls the system permission assignment endpoints and supplies high-privilege `roleId`, `menuIds`, `roleIds`, `dataScope`, or `dataScopeDeptIds`. The backend writes those RBAC/data-scope bindings without checking whether the operator is allowed to grant them

### 1.3 Key code evidence

1. `@ss.h`

Evidence location: @ss.h

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add grant-bound validation before writing assignment rows. For example, require that non-super-admin operators can only assign roles, menus, and data scopes within their own effective permissions and managed department scope

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/yudao-cloud/issue1.html
