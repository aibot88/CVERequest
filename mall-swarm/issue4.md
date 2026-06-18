---
title: "mall-swarm issue4: Cart updateAttr Soft Deletes Other User's Cart Item"
description: "mall-swarm has a missing authorization vulnerability in POST /mall-portal/cart/update/attr, POST /cart/update/attr. An authenticated attacker can operate on out-of-scope objects by supplying target identifiers."
tags:
  - mall-swarm
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall-swarm has a missing authorization vulnerability in POST /mall-portal/cart/update/attr, POST /cart/update/attr. An authenticated attacker can operate on out-of-scope objects by supplying target identifiers.

- Attack precondition: Any authenticated user
- Affected endpoint: `POST /mall-portal/cart/update/attr, POST /cart/update/attr`
- Affected authorization property: `id, OmsCartItemServiceImpl.updateAttr, deleteStatus=1, oms_cart_item.id -> oms_cart_item.member_id -> currentMember.id, updateAttr, memberId`
- Security impact: An authenticated attacker can operate on out-of-scope objects by supplying target identifiers.

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

Enforce server-side authorization for POST /mall-portal/cart/update/attr, POST /cart/update/attr before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall-swarm/issue4.html
