---
title: "yudao-cloud issue4: CRM Permission Update Can Modify Permission Rows Across Objects"
description: "yudao-cloud has a missing authorization vulnerability in PUT /crm/permission/update, bizType/bizId. The attacker can change `crm_permission.level` for another CRM object without being owner of that object, potentially upgrading a permission row to READ, WRITE, or OWNER"
tags:
  - yudao-cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

yudao-cloud has a missing authorization vulnerability in PUT /crm/permission/update, bizType/bizId. The attacker can change `crm_permission.level` for another CRM object without being owner of that object, potentially upgrading a permission row to READ, WRITE, or OWNER

- Attack precondition: Attacker has OWNER permission on CRM object A and knows the `crm_permission.id` of a permission row for object B
- Affected endpoint: `PUT /crm/permission/update, bizType/bizId`
- Affected authorization property: `crm_permission.id, @CrmPermission, ids, crm_permission.level, id, CrmPermissionController.updatePermission()`
- Security impact: The attacker can change `crm_permission.level` for another CRM object without being owner of that object, potentially upgrading a permission row to READ, WRITE, or OWNER

### 1.2 Exploit path

The attacker calls `PUT /crm/permission/update` with object A's `bizType/bizId` to satisfy the `@CrmPermission` check, but puts object B's permission row ID in `ids`. The service updates rows by primary key

### 1.3 Key code evidence

No concrete source path was extracted automatically. Review the issue body and source tree before final CVE submission.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Query all rows by `ids` before update and require every row's `bizType/bizId` to equal the authorized request object. Alternatively update with conditions on both `id` and `bizType/bizId`. Add a grant-bound check before raising a row to OWNER

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/yudao-cloud/issue4.html
