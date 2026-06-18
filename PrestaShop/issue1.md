---
title: "PrestaShop issue1: Legacy AdminAccess Tab Permission Update"
description: "PrestaShop has a missing authorization vulnerability in edit/UPDATE, CREATE/DELETE, CREATE/READ/UPDATE/DELETE. The attacker can grant a profile tab-level `CREATE` / `DELETE` permissions that exceed the current operator's own authorization. These rows are later trusted by the Back Office authorization system"
tags:
  - PrestaShop
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

PrestaShop has a missing authorization vulnerability in edit/UPDATE, CREATE/DELETE, CREATE/READ/UPDATE/DELETE. The attacker can grant a profile tab-level `CREATE` / `DELETE` permissions that exceed the current operator's own authorization. These rows are later trusted by the Back Office authorization system

- Attack precondition: Any authenticated user
- Affected endpoint: `edit/UPDATE, CREATE/DELETE, CREATE/READ/UPDATE/DELETE`
- Affected authorization property: `AdminAccess, CREATE, DELETE, access.id_profile, access.id_authorization_role, ajaxProcessUpdateAccess()`
- Security impact: The attacker can grant a profile tab-level `CREATE` / `DELETE` permissions that exceed the current operator's own authorization. These rows are later trusted by the Back Office authorization system

### 1.2 Exploit path

Send a crafted legacy AJAX request:

### 1.3 Key code evidence

1. `index.php`

Evidence location: index.php
2. `controllers/admin/AdminAccessController.php`

Evidence location: controllers/admin/AdminAccessController.php#L131
3. `classes/Access.php`

Evidence location: classes/Access.php#L223
4. `classes/Access.php`

Evidence location: classes/Access.php#L324
5. `src/PrestaShopBundle/Controller/Admin/Configure/AdvancedParameters/PermissionController.php`

Evidence location: src/PrestaShopBundle/Controller/Admin/Configure/AdvancedParameters/PermissionController.php#L68

## 2. Existing checks and why they fail

- Parameter allowlist only validates `perm` format, not authorization boundary. - `$this->access('edit')` proves only page update permission, not the right to grant `CREATE` or `DELETE`. - UI-side disabled check is bypassable and not a server-side control

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Before writing `add`, `delete`, or `all`, require the current employee to have the corresponding `CREATE` / `DELETE` authorization on `AdminAccess`, or route all updates through the migrated controller's stricter `create && update && delete` check

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/PrestaShop/issue1.html
