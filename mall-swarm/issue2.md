---
title: "mall-swarm issue2: Order Pay Success Unauthorized Update"
description: "mall-swarm has a missing authorization vulnerability in POST /mall-portal/order/paySuccess?orderId=...&payType=..., POST /order/paySuccess, POST /mall-portal/order/paySuccess?orderId=...&payType=, oms_order.status/payType/paymentTime. An authenticated attacker can perform authorization-sensitive operations through POST /mall-portal/order/paySuccess?orderId=...&payType=..., POST /order/paySuccess, POST /mall-portal/order/paySuccess?orderId=...&payType=, oms_order.status/payType/paymentTime without the required permission."
tags:
  - mall-swarm
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall-swarm has a missing authorization vulnerability in POST /mall-portal/order/paySuccess?orderId=...&payType=..., POST /order/paySuccess, POST /mall-portal/order/paySuccess?orderId=...&payType=, oms_order.status/payType/paymentTime. An authenticated attacker can perform authorization-sensitive operations through POST /mall-portal/order/paySuccess?orderId=...&payType=..., POST /order/paySuccess, POST /mall-portal/order/paySuccess?orderId=...&payType=, oms_order.status/payType/paymentTime without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `POST /mall-portal/order/paySuccess?orderId=...&payType=..., POST /order/paySuccess, POST /mall-portal/order/paySuccess?orderId=...&payType=, oms_order.status/payType/paymentTime`
- Affected authorization property: `orderId, OmsPortalOrderServiceImpl.paySuccess, status=1, payType, paymentTime, memberId`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through POST /mall-portal/order/paySuccess?orderId=...&payType=..., POST /order/paySuccess, POST /mall-portal/order/paySuccess?orderId=...&payType=, oms_order.status/payType/paymentTime without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to POST /mall-portal/order/paySuccess?orderId=...&payType=..., POST /order/paySuccess, POST /mall-portal/order/paySuccess?orderId=...&payType=, oms_order.status/payType/paymentTime with target identifiers or authorization-sensitive fields that should be rejected.

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

Enforce server-side authorization for POST /mall-portal/order/paySuccess?orderId=...&payType=..., POST /order/paySuccess, POST /mall-portal/order/paySuccess?orderId=...&payType=, oms_order.status/payType/paymentTime before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall-swarm/issue2.html
