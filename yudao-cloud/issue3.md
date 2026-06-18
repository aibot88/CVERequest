---
title: "yudao-cloud issue3: CRM Permission List Exposes Object Permission Bindings Without Object Authorization"
description: "yudao-cloud has a missing authorization vulnerability: CRM Permission List Exposes Object Permission Bindings Without Object Authorization. The endpoint leaks CRM ReBAC state: `crm_permission.id`, `userId`, `bizType`, `bizId`, and `level`. These fields are not merely display information; they drive subsequent `@CrmPermission` read/write/owner authorization"
tags:
  - yudao-cloud
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

yudao-cloud has a missing authorization vulnerability: CRM Permission List Exposes Object Permission Bindings Without Object Authorization. The endpoint leaks CRM ReBAC state: `crm_permission.id`, `userId`, `bizType`, `bizId`, and `level`. These fields are not merely display information; they drive subsequent `@CrmPermission` read/write/owner authorization

- Attack precondition: Attacker is an authenticated backend user and knows or can guess a CRM object's `bizType` and `bizId`
- Security impact: The endpoint leaks CRM ReBAC state: `crm_permission.id`, `userId`, `bizType`, `bizId`, and `level`. These fields are not merely display information; they drive subsequent `@CrmPermission` read/write/owner authorization

### 1.2 Exploit path

The attacker calls `GET /crm/permission/list?bizType=...&bizId=...` and receives the object's CRM permission rows, including users and permission levels

### 1.3 Key code evidence

No concrete source path was extracted automatically. Review the issue body and source tree before final CVE submission.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add `@CrmPermission(... level = READ)` or stricter OWNER permission to the list endpoint. Avoid returning permission row IDs to callers that do not need to modify those rows

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/yudao-cloud/issue3.html
