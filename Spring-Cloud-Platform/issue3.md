---
title: "Spring-Cloud-Platform issue3: 角色成员/负责人关系可被越权改写"
description: "Spring-Cloud-Platform has a missing authorization vulnerability: 角色成员/负责人关系可被越权改写. 攻击者可把任意用户加入任意高权限角色，包括管理员角色。后续授权查询会信任这些 membership 关系，从而造成权限提升。"
tags:
  - Spring-Cloud-Platform
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Spring-Cloud-Platform has a missing authorization vulnerability: 角色成员/负责人关系可被越权改写. 攻击者可把任意用户加入任意高权限角色，包括管理员角色。后续授权查询会信任这些 membership 关系，从而造成权限提升。

- Security impact: 攻击者可把任意用户加入任意高权限角色，包括管理员角色。后续授权查询会信任这些 membership 关系，从而造成权限提升。

### 1.2 Exploit path

`PUT /api/admin/group/{id}/user` 接收 path 中的目标 group id，以及请求参数 `members`、`leaders`。业务层先删除该组所有成员和负责人关系，再将攻击者传入的用户 id 插入 `base_group_member` 或 `base_group_leader`。

### 1.3 Key code evidence

1. `GroupController.java`

Evidence location: GroupController.java
2. `GroupBiz.java`

Evidence location: GroupBiz.java
3. `GroupMapper.xml`

Evidence location: GroupMapper.xml
4. `MenuMapper.xml`

Evidence location: MenuMapper.xml
5. `ElementMapper.xml`

Evidence location: ElementMapper.xml

## 2. Existing checks and why they fail

初始化数据中存在 `groupManager:btn_userManager` 权限项，但入口权限只说明用户可进入“分配用户”功能，不约束可操作哪个角色、可加入哪些用户、是否可授予高权限角色。代码中未发现角色层级、目标 group 管理权、下级用户范围或数据库约束兜底。

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

在 `modifyGroupUsers` 前校验当前用户是否可管理目标 group；限制只能授予不高于当前用户权限范围的角色；对 members/leaders 做可操作用户范围校验。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Spring-Cloud-Platform/issue3.html
