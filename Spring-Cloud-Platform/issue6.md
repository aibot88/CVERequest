---
title: "Spring-Cloud-Platform issue6: group-user 读取接口泄露成员关系和用户敏感字段"
description: "Spring-Cloud-Platform has a missing authorization vulnerability: group-user 读取接口泄露成员关系和用户敏感字段. 泄露角色成员/负责人关系以及用户密码哈希等敏感信息。成员关系本身也参与后续权限派生。"
tags:
  - Spring-Cloud-Platform
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Spring-Cloud-Platform has a missing authorization vulnerability: group-user 读取接口泄露成员关系和用户敏感字段. 泄露角色成员/负责人关系以及用户密码哈希等敏感信息。成员关系本身也参与后续权限派生。

- Security impact: 泄露角色成员/负责人关系以及用户密码哈希等敏感信息。成员关系本身也参与后续权限派生。

### 1.2 Exploit path

`GET /api/admin/group/{id}/user` 读取目标角色/组的成员与负责人。权限字典仅有 `PUT /admin/group/{*}/user` 分配用户动作，没有对应 GET 子资源；父级 `GET /admin/group/{*}` 被正则锚定，不能覆盖 `/user` 后缀。接口放行后返回 `GroupUsers`，底层 SQL join `base_user u.*`，包含 `password` 等用户敏感字段。

### 1.3 Key code evidence

1. `GroupController.java`

Evidence location: GroupController.java
2. `GroupBiz.java`

Evidence location: GroupBiz.java
3. `UserMapper.xml`

Evidence location: UserMapper.xml
4. `MenuMapper.xml`

Evidence location: MenuMapper.xml
5. `ElementMapper.xml`

Evidence location: ElementMapper.xml

## 2. Existing checks and why they fail

`PUT /admin/group/{*}/user` 不能覆盖 GET；`GET /admin/group/{*}` 不能覆盖 `/user` 子路径；响应未使用脱敏 DTO。

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

增加 `GET /admin/group/{*}/user` 权限项；校验当前用户是否可查看目标 group 成员；返回用户 DTO 并移除 `password` 等敏感字段。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Spring-Cloud-Platform/issue6.html
