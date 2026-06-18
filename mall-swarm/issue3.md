---
title: "mall-swarm issue3: Cancel Other User's Order"
description: "mall-swarm has a missing authorization vulnerability: Cancel Other User's Order. 可取消他人未付款订单，影响库存锁定、优惠券使用状态和积分返还。"
tags:
  - mall-swarm
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall-swarm has a missing authorization vulnerability: Cancel Other User's Order. 可取消他人未付款订单，影响库存锁定、优惠券使用状态和积分返还。

- Attack precondition: 任意已登录商城会员，知道他人未付款订单 ID。
- Security impact: 可取消他人未付款订单，影响库存锁定、优惠券使用状态和积分返还。

### 1.2 Exploit path

`POST /mall-portal/order/cancelUserOrder?orderId=...` -> `OmsPortalOrderServiceImpl.cancelOrder(orderId)` -> 按 `id/status/deleteStatus` 查询订单 -> 设置 `status=4` -> 释放库存并恢复优惠券/积分。

### 1.3 Key code evidence

1. `OmsPortalOrderServiceImpl.c`

Evidence location: OmsPortalOrderServiceImpl.c
2. `OmsPortalOrderController.java`

Evidence location: OmsPortalOrderController.java
3. `OmsPortalOrderServiceImpl.java`

Evidence location: OmsPortalOrderServiceImpl.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

用户取消订单时必须按 `orderId + currentMember.id + status=0` 查询并更新。自动超时取消应走内部任务/消息路径，不暴露为任意会员可指定订单的接口。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall-swarm/issue3.html
