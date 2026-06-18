---
title: "surveyking issue8: RBAC Grant Upper Bound Missing"
description: "surveyking has a missing authorization vulnerability: RBAC Grant Upper Bound Missing. 授予自己或他人更高权限，突破 RBAC 权限上界。"
tags:
  - surveyking
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

surveyking has a missing authorization vulnerability: RBAC Grant Upper Bound Missing. 授予自己或他人更高权限，突破 RBAC 权限上界。

- Attack precondition: 存在持有 `system:user:update` 或 `system:role:update`、但不应授予高权限角色/权限的管理员类用户。
- Security impact: 授予自己或他人更高权限，突破 RBAC 权限上界。

### 1.2 Exploit path

通过 `/api/system/user/update` 修改 `roles`，或 `/api/system/role/update` 修改 `authorities` / 绑定 `userIds`。

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

增加角色层级和授予上界校验；禁止操作者授予自己不具备或高于自身等级的角色/权限。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/surveyking/issue8.html
