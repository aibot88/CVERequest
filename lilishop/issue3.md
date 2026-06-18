---
title: "lilishop issue3: Issue 3"
description: "lilishop has a missing authorization vulnerability: Issue 3. 可跨店铺禁用或启用其他店铺店员。禁用会阻止该店员登录商家端。"
tags:
  - lilishop
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lilishop has a missing authorization vulnerability: Issue 3. 可跨店铺禁用或启用其他店铺店员。禁用会阻止该店员登录商家端。

- Attack precondition: 商家端已登录用户，拥有 `/store/clerk*` 非 GET 操作权限，且知道目标非店主 clerkId。
- Security impact: 可跨店铺禁用或启用其他店铺店员。禁用会阻止该店员登录商家端。

### 1.2 Exploit path

调用 `PUT /store/clerk/enable/{victimClerkId}?status=false` 或 `status=true`。

### 1.3 Key code evidence

1. `ClerkStoreController.java`

Evidence location: ClerkStoreController.java
2. `ClerkServiceImpl.java`

Evidence location: ClerkServiceImpl.java
3. `StoreTokenGenerate.java`

Evidence location: StoreTokenGenerate.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

在 `disable` 中增加 `clerk.getStoreId().equals(currentUser.getStoreId())` 校验；同时避免启用/禁用当前无权管理的店主或超级账号。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lilishop/issue3.html
