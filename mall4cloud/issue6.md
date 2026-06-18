---
title: "mall4cloud issue6: Attribute Update/Delete and Attribute-Category Edges Miss Ownership Checks"
description: "mall4cloud has a missing authorization vulnerability in PUT /admin/attr, DELETE /admin/attr, role.tenant_id/biz_type, menu_id/menu_permission_id, /role, /sys_user. A shop user with attribute management permission can alter or delete another shop's attributes, or create unauthorized attribute-category relationships"
tags:
  - mall4cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall4cloud has a missing authorization vulnerability in PUT /admin/attr, DELETE /admin/attr, role.tenant_id/biz_type, menu_id/menu_permission_id, /role, /sys_user. A shop user with attribute management permission can alter or delete another shop's attributes, or create unauthorized attribute-category relationships

- Attack precondition: Any authenticated user
- Affected endpoint: `PUT /admin/attr, DELETE /admin/attr, role.tenant_id/biz_type, menu_id/menu_permission_id, /role, /sys_user`
- Affected authorization property: ``attr.attr_id`, `attr.shop_id`, `attr_category.attr_id`, `attr_category.category_id``
- Security impact: A shop user with attribute management permission can alter or delete another shop's attributes, or create unauthorized attribute-category relationships

### 1.2 Exploit path

The attacker sends crafted requests to PUT /admin/attr, DELETE /admin/attr, role.tenant_id/biz_type, menu_id/menu_permission_id, /role, /sys_user with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `attr_category.c`

Evidence location: attr_category.c
2. `AttrMapper.xml`

Evidence location: AttrMapper.xml
3. `AttrCategoryMapper.xml`

Evidence location: AttrCategoryMapper.xml

## 2. Existing checks and why they fail

- `checkAttrInfo` forces shop users' `attrType` to sales attributes, but does not authorize the target `attrId`. - Category cache removal is not an authorization control. - There is no validation that submitted `categoryIds` belong to the allowed tenant or platform scope

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for PUT /admin/attr, DELETE /admin/attr, role.tenant_id/biz_type, menu_id/menu_permission_id, /role, /sys_user before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall4cloud/issue6.html
