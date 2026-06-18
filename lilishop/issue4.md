---
title: "lilishop issue4: Issue 4"
description: "lilishop has a missing authorization vulnerability: Issue 4. 跨店铺读取 clerk 元数据、`memberId`、`storeId`、`departmentId`、`roleIds`，并额外读取关联会员手机号和部门名称。"
tags:
  - lilishop
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lilishop has a missing authorization vulnerability: Issue 4. 跨店铺读取 clerk 元数据、`memberId`、`storeId`、`departmentId`、`roleIds`，并额外读取关联会员手机号和部门名称。

- Attack precondition: 商家端已登录用户，拥有 `/store/clerk*` GET 查询权限，且知道或能猜到 clerkId。
- Security impact: 跨店铺读取 clerk 元数据、`memberId`、`storeId`、`departmentId`、`roleIds`，并额外读取关联会员手机号和部门名称。

### 1.2 Exploit path

调用 `GET /store/clerk/{victimClerkId}`。

### 1.3 Key code evidence

1. `ClerkStoreController.java`

Evidence location: ClerkStoreController.java
2. `ClerkServiceImpl.java`

Evidence location: ClerkServiceImpl.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

`get(String id)` 中查询 clerk 后校验 `clerk.storeId == currentUser.storeId`；对不存在或无权统一返回 not found/authority error。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lilishop/issue4.html
