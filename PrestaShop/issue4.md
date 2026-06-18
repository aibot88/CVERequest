---
title: "PrestaShop issue4: Legacy AdminImport Direct Route Writes Customer/Address Bindings Under READ Permission"
description: "PrestaShop has a missing authorization vulnerability: Legacy AdminImport Direct Route Writes Customer/Address Bindings Under READ Permission. A user with only import view access may trigger database writes that create or update customers and addresses, including relationship-binding fields:"
tags:
  - PrestaShop
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

PrestaShop has a missing authorization vulnerability: Legacy AdminImport Direct Route Writes Customer/Address Bindings Under READ Permission. A user with only import view access may trigger database writes that create or update customers and addresses, including relationship-binding fields:

- Security impact: A user with only import view access may trigger database writes that create or update customers and addresses, including relationship-binding fields:

### 1.2 Exploit path

Use the legacy direct import route:

### 1.3 Key code evidence

1. `index.php`

Evidence location: index.php
2. `src/PrestaShopBundle/Controller/Admin/Configure/AdvancedParameters/ImportController.php`

Evidence location: src/PrestaShopBundle/Controller/Admin/Configure/AdvancedParameters/ImportController.php#L255
3. `src/PrestaShopBundle/Routing/LegacyRouterChecker.php`

Evidence location: src/PrestaShopBundle/Routing/LegacyRouterChecker.php#L169
4. `src/PrestaShopBundle/Controller/Admin/LegacyController.php`

Evidence location: src/PrestaShopBundle/Controller/Admin/LegacyController.php#L240
5. `controllers/admin/AdminImportController.php`

Evidence location: controllers/admin/AdminImportController.php#L3908
6. `controllers/admin/AdminImportController.php`

Evidence location: controllers/admin/AdminImportController.php#L342
7. `controllers/admin/AdminImportController.php`

Evidence location: controllers/admin/AdminImportController.php#L1019
8. `controllers/admin/AdminImportController.php`

Evidence location: controllers/admin/AdminImportController.php#L2718
9. `controllers/admin/AdminImportController.php`

Evidence location: controllers/admin/AdminImportController.php#L376
10. `controllers/admin/AdminImportController.php`

Evidence location: controllers/admin/AdminImportController.php#L3025
11. `controllers/admin/AdminImportController.php`

Evidence location: controllers/admin/AdminImportController.php#L3155

## 2. Existing checks and why they fail

- Valid admin token is still required, so this is not unauthenticated.
- The secure Symfony route is not the vulnerable path.
- Customer/address validation checks existence and field validity, but does not check whether the employee may bind customers/addresses to the selected shop/customer/group.
- The legacy permission mapper treats `import=1` as READ, which is insufficient for a write operation.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Map legacy `import=1` to a write permission, ideally requiring `create && update && delete` like the migrated process endpoint. Also add explicit permission checks in `AdminImportController::postProcess()` before `importByGroups()`, and validate imported `id_shop`, `id_customer`, and group bindings against the current employee's authorized scope

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/PrestaShop/issue4.html
