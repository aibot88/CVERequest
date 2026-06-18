---
title: "mall4cloud issue5: Category Update/Delete Misses `category.shop_id` Ownership Check"
description: "mall4cloud has a missing authorization vulnerability in PUT /admin/category, DELETE /admin/category. A shop user with category management permission can modify or delete another shop's category, affecting classification and product organization"
tags:
  - mall4cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall4cloud has a missing authorization vulnerability in PUT /admin/category, DELETE /admin/category. A shop user with category management permission can modify or delete another shop's category, affecting classification and product organization

- Attack precondition: Any authenticated user
- Affected endpoint: `PUT /admin/category, DELETE /admin/category`
- Affected authorization property: ``category.category_id`, `category.shop_id`, `category.parent_id``
- Security impact: A shop user with category management permission can modify or delete another shop's category, affecting classification and product organization

### 1.2 Exploit path

The attacker sends crafted requests to PUT /admin/category, DELETE /admin/category with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `category.c`

Evidence location: category.c
2. `CategoryMapper.xml`

Evidence location: CategoryMapper.xml

## 2. Existing checks and why they fail

- Duplicate-name validation sets current `shopId`, but that is a uniqueness check, not an authorization check on the target category. - Use-count checks prevent deleting categories in use, but do not enforce tenant ownership

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for PUT /admin/category, DELETE /admin/category before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall4cloud/issue5.html
