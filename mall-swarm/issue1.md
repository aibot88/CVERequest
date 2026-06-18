---
title: "mall-swarm issue1: Order Detail Unauthorized Read"
description: "mall-swarm has a missing authorization vulnerability: Order Detail Unauthorized Read. 可越权读取他人订单详情，包括订单归属、商品明细、收货人、电话、收货地址等非公开信息。"
tags:
  - mall-swarm
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall-swarm has a missing authorization vulnerability: Order Detail Unauthorized Read. 可越权读取他人订单详情，包括订单归属、商品明细、收货人、电话、收货地址等非公开信息。

- Attack precondition: 任意已登录商城会员，知道或猜到他人 `orderId`。
- Security impact: 可越权读取他人订单详情，包括订单归属、商品明细、收货人、电话、收货地址等非公开信息。

### 1.2 Exploit path

`GET /mall-portal/order/detail/{orderId}` -> `OmsPortalOrderServiceImpl.detail(orderId)` -> `orderMapper.selectByPrimaryKey(orderId)` -> 返回 `OmsOrderDetail`。

### 1.3 Key code evidence

1. `OmsPortalOrderController.java`

Evidence location: OmsPortalOrderController.java
2. `OmsPortalOrderServiceImpl.java`

Evidence location: OmsPortalOrderServiceImpl.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

使用 `orderId + currentMember.id` 查询订单；若不存在则返回 404/403。订单项也应只在订单归属校验成功后加载。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall-swarm/issue1.html
