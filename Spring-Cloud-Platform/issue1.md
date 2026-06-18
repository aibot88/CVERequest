---
title: "Spring-Cloud-Platform issue1: 角色菜单权限关系可被越权改写"
description: "Spring-Cloud-Platform has a missing authorization vulnerability: 角色菜单权限关系可被越权改写. 低权限用户可以给任意角色授予菜单权限，污染后续 RBAC 权限派生结果。"
tags:
  - Spring-Cloud-Platform
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Spring-Cloud-Platform has a missing authorization vulnerability: 角色菜单权限关系可被越权改写. 低权限用户可以给任意角色授予菜单权限，污染后续 RBAC 权限派生结果。

- Security impact: 低权限用户可以给任意角色授予菜单权限，污染后续 RBAC 权限派生结果。

### 1.2 Exploit path

`PUT /api/admin/group/{id}/authority/menu?menuTrees=...` 经网关进入权限检查。网关使用真实请求 method/path 查询权限，但初始化权限字典中菜单授权项是 `POST /admin/group/{*}/authority/menu`，真实接口是 `PUT /group/{id}/authority/menu`。未命中权限资源后，`PermissionService` 将其视为“不受控资源”并放行。随后业务层删除目标角色旧菜单授权并写入新的 `base_resource_authority` 记录。

### 1.3 Key code evidence

1. `GroupController.java`

Evidence location: GroupController.java
2. `GroupBiz.java`

Evidence location: GroupBiz.java
3. `MenuMapper.xml`

Evidence location: MenuMapper.xml
4. `AccessGatewayFilter.java`

Evidence location: AccessGatewayFilter.java
5. `PermissionService.java`

Evidence location: PermissionService.java
6. `init.sql`

Evidence location: init.sql

## 2. Existing checks and why they fail

JWT 只证明用户已登录；网关权限检查因 method/path 错配 fail-open；业务层没有检查当前用户是否可管理目标角色，也没有检查授予权限是否超过当前用户权限上界。

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

修正权限字典为真实 `PUT /admin/group/{*}/authority/menu`；管理类资源未匹配时默认拒绝；写入前校验当前用户可管理目标 group 且可授予每个 menu。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Spring-Cloud-Platform/issue1.html
