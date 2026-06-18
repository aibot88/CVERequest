---
title: "mall-swarm issue6: Return Apply Unauthorized Creation"
description: "mall-swarm has a missing authorization vulnerability: Return Apply Unauthorized Creation. 可为他人订单/商品创建退货申请，污染售后流程，并可能影响后台处理和退款/退货状态。"
tags:
  - mall-swarm
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall-swarm has a missing authorization vulnerability: Return Apply Unauthorized Creation. 可为他人订单/商品创建退货申请，污染售后流程，并可能影响后台处理和退款/退货状态。

- Attack precondition: 任意已登录商城会员，知道或构造目标 `orderId/productId/orderSn/memberUsername`。
- Security impact: 可为他人订单/商品创建退货申请，污染售后流程，并可能影响后台处理和退款/退货状态。

### 1.2 Exploit path

`POST /mall-portal/returnApply/create` -> request body `OmsOrderReturnApplyParam` -> `BeanUtils.copyProperties(returnApply, realApply)` -> insert into `oms_order_return_apply`

### 1.3 Key code evidence

1. `BeanUtils.c`

Evidence location: BeanUtils.c
2. `OmsPortalOrderReturnApplyController.java`

Evidence location: OmsPortalOrderReturnApplyController.java
3. `OmsPortalOrderReturnApplyServiceImpl.java`

Evidence location: OmsPortalOrderReturnApplyServiceImpl.java
4. `OmsOrderReturnApplyParam.java`

Evidence location: OmsOrderReturnApplyParam.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Do not trust request body for binding fields. Query order and order item by `orderId + currentMember.id`, verify `productId` belongs to that order, then server-side populate `orderSn`, `memberUsername`, product fields, and return applicant fields

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall-swarm/issue6.html
