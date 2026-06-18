---
title: "pig issue1: User Authorization Binding Write Without Grant Boundary"
description: "pig has a missing authorization vulnerability in - `POST /user`. A non-superadmin user with limited user-management/import capability can create or modify users with roles or organizational bindings beyond the attacker's own authority, potentially escalating to administrator privileges"
tags:
  - pig
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

pig has a missing authorization vulnerability in - `POST /user`. A non-superadmin user with limited user-management/import capability can create or modify users with roles or organizational bindings beyond the attacker's own authority, potentially escalating to administrator privileges

- Attack precondition: Any authenticated user
- Affected endpoint: `- `POST /user``
- Affected authorization property: `sys_user_role.user_id, sys_user_role.role_id, sys_user_dept.user_id, sys_user_dept.dept_id, sys_user_post.user_id, sys_user_post.post_id`
- Security impact: A non-superadmin user with limited user-management/import capability can create or modify users with roles or organizational bindings beyond the attacker's own authority, potentially escalating to administrator privileges

### 1.2 Exploit path

1. Attacker has user-management or user-import permission. 2. Attacker submits a request or Excel row containing a privileged role, such as the administrator role name/ID. 3. Service code resolves or accepts the role and writes it into `sys_user_role`. 4. The target/new user logs in and receives authorities derived from that role

### 1.3 Key code evidence

1. `SysUserController.java`

Evidence location: SysUserController.java
2. `SysUserServiceImpl.java`

Evidence location: SysUserServiceImpl.java
3. `PigUserDetailsService.java`

Evidence location: PigUserDetailsService.java

## 2. Existing checks and why they fail

- Entry checks (`sys_user_add`, `sys_user_edit`, `sys_user_export`) protect the action, not the authorization boundary of assigned roles/departments/posts. - The import path validates that role/dept/post names exist, but not whether the current user can grant them. - No role hierarchy, grantable-role whitelist, department scope check, or self-escalation guard is enforced

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add grant-boundary checks for role, department, and post assignment. - Ensure a user can only assign roles/organizations they are allowed to manage. - Reuse one centralized user creation/update service for normal and import flows. - Split import/export permission into explicit `sys_user_import` and `sys_user_export`, and require import to satisfy the same authorization checks as user creation

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/pig/issue1.html
