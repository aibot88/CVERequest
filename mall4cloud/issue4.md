---
title: "mall4cloud issue4: Product Update/Delete Misses `spu.shop_id` Ownership Check"
description: "mall4cloud has a missing authorization vulnerability in PUT /admin/spu, DELETE /admin/spu, PUT /admin/spu/update_spu_data. A shop user with product management permission can modify or delete another shop's product, including product metadata, category links, details, SKU-related updates, and stock-adjacent fields"
tags:
  - mall4cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall4cloud has a missing authorization vulnerability in PUT /admin/spu, DELETE /admin/spu, PUT /admin/spu/update_spu_data. A shop user with product management permission can modify or delete another shop's product, including product metadata, category links, details, SKU-related updates, and stock-adjacent fields

- Attack precondition: Any authenticated user
- Affected endpoint: `PUT /admin/spu, DELETE /admin/spu, PUT /admin/spu/update_spu_data`
- Affected authorization property: ``spu.shop_id`, `spu.spu_id``
- Security impact: A shop user with product management permission can modify or delete another shop's product, including product metadata, category links, details, SKU-related updates, and stock-adjacent fields

### 1.2 Exploit path

The attacker sends crafted requests to PUT /admin/spu, DELETE /admin/spu, PUT /admin/spu/update_spu_data with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

No concrete source path was extracted automatically. Review the issue body and source tree before final CVE submission.

## 2. Existing checks and why they fail

- Route RBAC checks only the action permission, not ownership of the target product. - `checkSaveOrUpdateInfo` validates required category fields, not target product ownership. - Mapper updates use `WHERE spu_id =...`, not `WHERE spu_id =... AND shop_id = currentTenant`

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for PUT /admin/spu, DELETE /admin/spu, PUT /admin/spu/update_spu_data before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall4cloud/issue4.html
