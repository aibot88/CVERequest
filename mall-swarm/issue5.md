---
title: "mall-swarm issue5: Member Read History Unauthorized Delete"
description: "mall-swarm has a missing authorization vulnerability: Member Read History Unauthorized Delete. 可删除他人的浏览历史记录。"
tags:
  - mall-swarm
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall-swarm has a missing authorization vulnerability: Member Read History Unauthorized Delete. 可删除他人的浏览历史记录。

- Attack precondition: 任意已登录商城会员，知道他人浏览历史 Mongo `_id`。
- Security impact: 可删除他人的浏览历史记录。

### 1.2 Exploit path

`POST /mall-portal/member/readHistory/delete` with `ids` -> `MemberReadHistoryServiceImpl.delete` -> constructs entities containing only `_id` -> `memberReadHistoryRepository.deleteAll(deleteList)`

### 1.3 Key code evidence

1. `MemberReadHistoryController.java`

Evidence location: MemberReadHistoryController.java
2. `MemberReadHistoryServiceImpl.java`

Evidence location: MemberReadHistoryServiceImpl.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

删除时按 `id in ids AND memberId=currentMember.id` 执行；对不属于当前会员的 id 忽略或返回错误。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall-swarm/issue5.html
