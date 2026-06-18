---
title: "mall-swarm issue2: Order Pay Success Unauthorized Update"
description: "mall-swarm has a missing authorization vulnerability: Order Pay Success Unauthorized Update. 可伪造他人订单支付成功状态，触发库存扣减，扰乱订单履约流程。"
tags:
  - mall-swarm
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall-swarm has a missing authorization vulnerability: Order Pay Success Unauthorized Update. 可伪造他人订单支付成功状态，触发库存扣减，扰乱订单履约流程。

- Attack precondition: 任意已登录商城会员，知道有效 `orderId`。
- Security impact: 可伪造他人订单支付成功状态，触发库存扣减，扰乱订单履约流程。

### 1.2 Exploit path

`POST /mall-portal/order/paySuccess?orderId=...&payType=...` -> `OmsPortalOrderServiceImpl.paySuccess` -> 按主键更新 `status=1`、`payType`、`paymentTime` -> 读取订单项并扣减库存。

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

移除用户可直接调用的支付成功接口；只接受支付平台签名回调。回调内部按订单号查询订单并校验状态、金额、支付来源。若保留会员触发查询，也只能查询支付状态，不能直接改订单。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall-swarm/issue2.html
