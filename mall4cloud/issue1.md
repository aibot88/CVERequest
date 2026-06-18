---
title: "mall4cloud issue1: User Role Assignment Writes Arbitrary `role_id`"
description: "mall4cloud has a missing authorization vulnerability in POST /sys_user, PUT /sys_user, POST /m/shop_user, PUT /m/shop_user, SysUserServiceImpl.save/update, ShopUserServiceImpl.save/update. A user who can manage users may assign roles outside the intended grant scope, potentially giving a platform or shop user unauthorized permissions"
tags:
  - mall4cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall4cloud has a missing authorization vulnerability in POST /sys_user, PUT /sys_user, POST /m/shop_user, PUT /m/shop_user, SysUserServiceImpl.save/update, ShopUserServiceImpl.save/update. A user who can manage users may assign roles outside the intended grant scope, potentially giving a platform or shop user unauthorized permissions

- Attack precondition: Any authenticated user
- Affected endpoint: `POST /sys_user, PUT /sys_user, POST /m/shop_user, PUT /m/shop_user, SysUserServiceImpl.save/update, ShopUserServiceImpl.save/update`
- Affected authorization property: ``user_role.user_id`, `user_role.role_id`, `role.biz_type`, `role.tenant_id``
- Security impact: A user who can manage users may assign roles outside the intended grant scope, potentially giving a platform or shop user unauthorized permissions

### 1.2 Exploit path

The attacker sends crafted requests to POST /sys_user, PUT /sys_user, POST /m/shop_user, PUT /m/shop_user, SysUserServiceImpl.save/update, ShopUserServiceImpl.save/update with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `UserRoleMapper.xml`

Evidence location: UserRoleMapper.xml
2. `MenuPermissionMapper.xml`

Evidence location: MenuPermissionMapper.xml

## 2. Existing checks and why they fail

- Route RBAC proves the caller has the endpoint action permission, not that they may grant every submitted `role_id`. - Shop user update/delete validates the target `shop_user.shop_id`, but role IDs are not validated against `role.tenant_id`. - Role list APIs being tenant-scoped is only a UI/data-source constraint; it is not enforced at the write sink

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for POST /sys_user, PUT /sys_user, POST /m/shop_user, PUT /m/shop_user, SysUserServiceImpl.save/update, ShopUserServiceImpl.save/update before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall4cloud/issue1.html
