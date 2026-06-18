---
title: "Spring-Cloud-Platform issue5: 未授权新增菜单污染全局权限定义"
description: "Spring-Cloud-Platform has a missing authorization vulnerability: 未授权新增菜单污染全局权限定义. 攻击者可未授权写入全局权限定义来源。`PermissionService.getAllPermission()` 会把 `base_menu` 中所有菜单转换为全局 `PermissionInfo`，影响系统对资源权限的定义和匹配。"
tags:
  - Spring-Cloud-Platform
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Spring-Cloud-Platform has a missing authorization vulnerability: 未授权新增菜单污染全局权限定义. 攻击者可未授权写入全局权限定义来源。`PermissionService.getAllPermission()` 会把 `base_menu` 中所有菜单转换为全局 `PermissionInfo`，影响系统对资源权限的定义和匹配。

- Security impact: 攻击者可未授权写入全局权限定义来源。`PermissionService.getAllPermission()` 会把 `base_menu` 中所有菜单转换为全局 `PermissionInfo`，影响系统对资源权限的定义和匹配。

### 1.2 Exploit path

`POST /api/admin/menu` 由 `MenuController` 继承通用 `BaseController.add`。初始化权限字典将新增菜单权限登记为 `POST /admin/menu/{*}`，但真实新增接口没有 id 段，是 `POST /admin/menu`。权限检查未命中后默认放行，业务层写入 `base_menu`，并由 `MenuBiz` 派生 `path`。

### 1.3 Key code evidence

1. `MenuController.java`

Evidence location: MenuController.java
2. `BaseController.java`

Evidence location: BaseController.java
3. `MenuBiz.java`

Evidence location: MenuBiz.java
4. `PermissionService.java`

Evidence location: PermissionService.java
5. `init.sql`

Evidence location: init.sql

## 2. Existing checks and why they fail

JWT 只证明登录；权限路径登记错误导致 fail-open；未看到仅管理员可写权限定义的服务端检查或字段白名单限制。

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

修正新增菜单权限为 `POST /admin/menu`；管理类未匹配资源默认拒绝；限制只有高权限管理员可写 `base_menu` 中影响授权模型的字段。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Spring-Cloud-Platform/issue5.html
