---
title: "lilishop issue2: Issue 2"
description: "lilishop has a missing authorization vulnerability: Issue 2. 可读取或替换其他店铺部门继承的角色，影响该部门店员后续权限。"
tags:
  - lilishop
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lilishop has a missing authorization vulnerability: Issue 2. 可读取或替换其他店铺部门继承的角色，影响该部门店员后续权限。

- Attack precondition: 商家端已登录用户，拥有 `/store/departmentRole*` 非 GET 操作权限，或店铺超级管理员。
- Security impact: 可读取或替换其他店铺部门继承的角色，影响该部门店员后续权限。

### 1.2 Exploit path

调用 `PUT /store/departmentRole/{victimDepartmentId}`，路径使用其他店铺部门 ID，body 提交新的 `StoreDepartmentRole`。

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

在 `listByDepartmentId/updateByDepartmentId` 中查询 `StoreDepartment` 校验归属；校验提交的 `roleId` 均属于当前店铺；强制 body `departmentId` 与路径一致。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lilishop/issue2.html
