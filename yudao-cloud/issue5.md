---
title: "yudao-cloud issue5: CRM Customer Import Can Assign Arbitrary Owner and Derive OWNER Permission"
description: "yudao-cloud has a missing authorization vulnerability in POST /crm/customer/import, crm_permission.userId/level=OWNER. The attacker can create CRM customers assigned to arbitrary users and create corresponding `crm_permission` OWNER bindings. This bypasses the separate customer distribution permission boundary"
tags:
  - yudao-cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

yudao-cloud has a missing authorization vulnerability in POST /crm/customer/import, crm_permission.userId/level=OWNER. The attacker can create CRM customers assigned to arbitrary users and create corresponding `crm_permission` OWNER bindings. This bypasses the separate customer distribution permission boundary

- Attack precondition: Attacker has `crm:customer:import` but should not have arbitrary customer distribution authority
- Affected endpoint: `POST /crm/customer/import, crm_permission.userId/level=OWNER`
- Affected authorization property: `crm:customer:import, ownerUserId, crm_permission, crm_customer.owner_user_id, crm:customer:distribute, CrmCustomerController.importExcel()`
- Security impact: The attacker can create CRM customers assigned to arbitrary users and create corresponding `crm_permission` OWNER bindings. This bypasses the separate customer distribution permission boundary

### 1.2 Exploit path

The attacker submits `POST /crm/customer/import` with a multipart `ownerUserId` and an Excel file containing new customers. The import path writes the supplied owner and creates OWNER permission for that user

### 1.3 Key code evidence

No concrete source path was extracted automatically. Review the issue body and source tree before final CVE submission.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

For import, either force owner to the current login user/null or require `crm:customer:distribute` when `ownerUserId` is supplied. Also validate target owner scope, department/subordinate relationship, and customer ownership limits

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/yudao-cloud/issue5.html
