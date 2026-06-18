---
title: "lilishop issue1: Issue 1"
description: "lilishop has a missing authorization vulnerability: Issue 1. 可读取、删除、替换其他店铺角色的菜单权限绑定，导致跨店铺权限破坏或权限授予。"
tags:
  - lilishop
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lilishop has a missing authorization vulnerability: Issue 1. 可读取、删除、替换其他店铺角色的菜单权限绑定，导致跨店铺权限破坏或权限授予。

- Attack precondition: 商家端已登录用户，拥有 `/store/roleMenu*` 非 GET 操作权限，或 `isSuper=true` 的店铺管理员。
- Security impact: 可读取、删除、替换其他店铺角色的菜单权限绑定，导致跨店铺权限破坏或权限授予。

### 1.2 Exploit path

调用 `POST /store/roleMenu/{victimRoleId}`，路径使用其他店铺的 `roleId`。服务端按该 `roleId` 删除原菜单绑定，再保存攻击者提交的 `StoreMenuRole` 列表。

### 1.3 Key code evidence

1. `StoreMenuRoleController.java`

Evidence location: StoreMenuRoleController.java
2. `StoreMenuRoleServiceImpl.java`

Evidence location: StoreMenuRoleServiceImpl.java
3. `StoreMenuMapper.java`

Evidence location: StoreMenuMapper.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

在 `findByRoleId/updateRoleMenu/delete` 前查询 `StoreRole` 并校验 `storeId == currentUser.storeId`；强制 body 每条 `roleId = path roleId`，并校验 `menuId` 是合法店铺菜单。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lilishop/issue1.html
