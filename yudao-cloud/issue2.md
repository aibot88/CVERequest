---
title: "yudao-cloud issue2: User Department Assignment Can Bypass Data Permission Boundaries"
description: "yudao-cloud has a missing authorization vulnerability. `AdminUserDO.deptId` is used by the department data permission model. Changing a user's department can alter later data permission calculation for roles using \"current department\" or \"current department and children\" scopes"
tags:
  - yudao-cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

yudao-cloud has a missing authorization vulnerability. `AdminUserDO.deptId` is used by the department data permission model. Changing a user's department can alter later data permission calculation for roles using "current department" or "current department and children" scopes

- Attack precondition: Attacker has user create/update/import permissions such as `system:user:create`, `system:user:update`, or user import capability, but should not be allowed to place users into arbitrary departments
- Affected authorization property: `system:user:create, system:user:update, deptId, postIds, AdminUserDO.deptId, UserSaveReqVO`
- Security impact: `AdminUserDO.deptId` is used by the department data permission model. Changing a user's department can alter later data permission calculation for roles using "current department" or "current department and children" scopes

### 1.2 Exploit path

The attacker creates, updates, or imports users with an arbitrary `deptId` and optional `postIds`. The backend validates only existence/enabled state and writes the new department relation

### 1.3 Key code evidence

1. `UserController.c`

Evidence location: UserController.c
2. `AdminUserServiceImpl.c`

Evidence location: AdminUserServiceImpl.c

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Before create/update/import, verify the operator can manage the target `deptId` and the old user's department. For imports, apply the same validation row by row. Treat `postIds` similarly if posts are intended to be scoped by department or management hierarchy

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/yudao-cloud/issue2.html
