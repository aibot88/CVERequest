---
title: "platform issue9: Role Resource Assignment Lacks Grantable-Resource Upper Bound"
description: "platform has a missing authorization vulnerability: Role Resource Assignment Lacks Grantable-Resource Upper Bound. Grants permissions the actor does not possess to arbitrary roles"
tags:
  - platform
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

platform has a missing authorization vulnerability: Role Resource Assignment Lacks Grantable-Resource Upper Bound. Grants permissions the actor does not possess to arbitrary roles

- Attack precondition: The attacker has `sys:role:assign-resource`, but not necessarily the resources being granted
- Security impact: Grants permissions the actor does not possess to arbitrary roles

### 1.2 Exploit path

Use `PUT /roles/{roleId}/assign-resources` with arbitrary `req.roleId` and `resIdList`

### 1.3 Key code evidence

1. `RoleController.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/RoleController.java#L130
2. `RoleResServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/RoleResServiceImpl.java#L67

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Use the path `roleId`, validate target role manageability, and enforce `resIdList ⊆ current_user.grantableResources`

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/platform/issue9.html
