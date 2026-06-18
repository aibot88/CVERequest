---
title: "PrestaShop issue2: Legacy AdminAccess Module Uninstall Permission Update"
description: "PrestaShop has a missing authorization vulnerability in edit/UPDATE, configure/edit, uninstall/delete. The attacker can grant a profile module `uninstall` permission, which maps to a `DELETE` authorization role and enables destructive module operations"
tags:
  - PrestaShop
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

PrestaShop has a missing authorization vulnerability in edit/UPDATE, configure/edit, uninstall/delete. The attacker can grant a profile module `uninstall` permission, which maps to a `DELETE` authorization role and enables destructive module operations

- Attack precondition: Any authenticated user
- Affected endpoint: `edit/UPDATE, configure/edit, uninstall/delete`
- Affected authorization property: `AdminAccess, DELETE, uninstall, module_access.id_profile, module_access.id_authorization_role, ajaxProcessUpdateModuleAccess()`
- Security impact: The attacker can grant a profile module `uninstall` permission, which maps to a `DELETE` authorization role and enables destructive module operations

### 1.2 Exploit path

Send a crafted legacy AJAX request:

### 1.3 Key code evidence

1. `index.php`

Evidence location: index.php
2. `controllers/admin/AdminAccessController.php`

Evidence location: controllers/admin/AdminAccessController.php#L156
3. `classes/Access.php`

Evidence location: classes/Access.php#L223
4. `classes/Access.php`

Evidence location: classes/Access.php#L384
5. `classes/module/Module.php`

Evidence location: classes/module/Module.php#L2728
6. `src/PrestaShopBundle/Controller/Admin/Configure/AdvancedParameters/PermissionController.php`

Evidence location: src/PrestaShopBundle/Controller/Admin/Configure/AdvancedParameters/PermissionController.php#L102

## 2. Existing checks and why they fail

- `configure/edit` and `uninstall/delete` are separate capabilities. - The endpoint validates the permission name, but does not enforce that the current employee may grant a DELETE-class permission

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Require `DELETE` permission when `perm=uninstall`, or use the migrated controller's stricter combined permission requirement for all module permission updates

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/PrestaShop/issue2.html
