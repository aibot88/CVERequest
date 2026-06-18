---
title: "Spring-Cloud-Platform issue2: 角色按钮/API 权限关系可被越权增删"
description: "Spring-Cloud-Platform has a missing authorization vulnerability: 角色按钮/API 权限关系可被越权增删. 攻击者可给角色增加或移除按钮/API 权限，影响后续接口级授权。"
tags:
  - Spring-Cloud-Platform
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Spring-Cloud-Platform has a missing authorization vulnerability: 角色按钮/API 权限关系可被越权增删. 攻击者可给角色增加或移除按钮/API 权限，影响后续接口级授权。

- Security impact: 攻击者可给角色增加或移除按钮/API 权限，影响后续接口级授权。

### 1.2 Exploit path

`PUT /api/admin/group/{id}/authority/element/add` 或 `PUT /api/admin/group/{id}/authority/element/remove` 访问真实接口。初始化权限字典只有 `POST /admin/group/{*}/authority/element`，没有真实 `PUT` method，也没有 `/add`、`/remove` 子路径。权限检查未命中后默认放行，业务层直接插入或删除 `base_resource_authority` 中的 button 授权关系。

### 1.3 Key code evidence

1. `GroupController.java`

Evidence location: GroupController.java
2. `GroupBiz.java`

Evidence location: GroupBiz.java
3. `ElementMapper.xml`

Evidence location: ElementMapper.xml
4. `init.sql`

Evidence location: init.sql

## 2. Existing checks and why they fail

`menuId` 参数未参与授权校验；无 resourceId 归属检查、角色管理权检查或“只能授予已有权限”检查；网关因 method/path 错配 fail-open。

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

登记真实 add/remove 权限项；写入和删除前校验当前用户对目标 group 和 element 的管理/授予权限；避免未匹配权限资源默认放行。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Spring-Cloud-Platform/issue2.html
