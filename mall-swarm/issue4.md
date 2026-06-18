---
title: "mall-swarm issue4: Cart updateAttr Soft Deletes Other User's Cart Item"
description: "mall-swarm has a missing authorization vulnerability: Cart updateAttr Soft Deletes Other User's Cart Item. 可软删除他人的购物车项。"
tags:
  - mall-swarm
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall-swarm has a missing authorization vulnerability: Cart updateAttr Soft Deletes Other User's Cart Item. 可软删除他人的购物车项。

- Attack precondition: 任意已登录商城会员，知道他人购物车项 `id`。
- Security impact: 可软删除他人的购物车项。

### 1.2 Exploit path

`POST /mall-portal/cart/update/attr` with another user's cart item `id` -> `OmsCartItemServiceImpl.updateAttr` -> old cart item is updated by primary key with `deleteStatus=1` -> new item is added for current user

### 1.3 Key code evidence

1. `OmsCartItemController.java`

Evidence location: OmsCartItemController.java
2. `OmsCartItemServiceImpl.java`

Evidence location: OmsCartItemServiceImpl.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

在 `updateAttr` 中使用当前会员 ID 查询/更新旧项，例如 `id + currentMember.id + deleteStatus=0`；未匹配时返回 403/404。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall-swarm/issue4.html
