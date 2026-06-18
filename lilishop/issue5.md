---
title: "lilishop issue5: Issue 5"
description: "lilishop has a missing authorization vulnerability: Issue 5. 可把本店其他 clerk 直接提升为商家端超级管理员；也可能通过跨店铺 roleId/departmentId 引入不属于本店的权限绑定。"
tags:
  - lilishop
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lilishop has a missing authorization vulnerability: Issue 5. 可把本店其他 clerk 直接提升为商家端超级管理员；也可能通过跨店铺 roleId/departmentId 引入不属于本店的权限绑定。

- Attack precondition: 商家端已登录用户，拥有 `/store/clerk*` 非 GET 操作权限，可编辑本店非店主 clerk。
- Security impact: 可把本店其他 clerk 直接提升为商家端超级管理员；也可能通过跨店铺 roleId/departmentId 引入不属于本店的权限绑定。

### 1.2 Exploit path

调用 `PUT /store/clerk/{ownStoreClerkId}`，提交 `isSuper=true`，或提交其他店铺/更高权限角色 ID、其他店铺部门 ID。

### 1.3 Key code evidence

1. `ClerkStoreController.java`

Evidence location: ClerkStoreController.java
2. `ClerkServiceImpl.java`

Evidence location: ClerkServiceImpl.java
3. `StoreAuthenticationFilter.java`

Evidence location: StoreAuthenticationFilter.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

只有当前 `isSuper` 或店主可授予/撤销 `isSuper`；编辑时复用新增路径的 role 店铺归属校验；部门必须校验 `department.storeId == currentUser.storeId`；可增加“不能授予超过操作者自身权限集合”的上界校验。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lilishop/issue5.html
