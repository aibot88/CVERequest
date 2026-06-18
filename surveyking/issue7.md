---
title: "surveyking issue7: System User Position Permission Boundary Bypass"
description: "surveyking has a missing authorization vulnerability: System User Position Permission Boundary Bypass. 绕过独立岗位更新权限，修改用户的部门/岗位绑定；该绑定后续参与工作流用户组解析。"
tags:
  - surveyking
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

surveyking has a missing authorization vulnerability: System User Position Permission Boundary Bypass. 绕过独立岗位更新权限，修改用户的部门/岗位绑定；该绑定后续参与工作流用户组解析。

- Attack precondition: 持有 `system:user:update` 的用户，不需要持有独立的 `system:user:updatePosition`。
- Security impact: 绕过独立岗位更新权限，修改用户的部门/岗位绑定；该绑定后续参与工作流用户组解析。

### 1.2 Exploit path

调用 `POST /api/system/user/update`，在请求体中携带 `userPositions`。

### 1.3 Key code evidence

1. `SystemApi.java`

Evidence location: SystemApi.java#L175
2. `SystemApi.java`

Evidence location: SystemApi.java#L186
3. `UserServiceImpl.java`

Evidence location: UserServiceImpl.java#L273
4. `UserServiceImpl.java`

Evidence location: UserServiceImpl.java#L318

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

在 `updateUser` 中忽略 `userPositions`，或要求同时具备 `system:user:updatePosition`。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/surveyking/issue7.html
