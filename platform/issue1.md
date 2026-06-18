---
title: "platform issue1: Data Permission Assignment Missing Authorization"
description: "platform has a missing authorization vulnerability: Data Permission Assignment Missing Authorization. The attacker can expand role/user data visibility by modifying authorization-model records in `sys_data_permission_ref`"
tags:
  - platform
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

platform has a missing authorization vulnerability: Data Permission Assignment Missing Authorization. The attacker can expand role/user data visibility by modifying authorization-model records in `sys_data_permission_ref`

- Attack precondition: The attacker is authenticated and can reach `PUT /data-permissions/{ownerType}/{ownerId}`. The impact is clearest when the target role has `scopeType=CUSTOMIZE`
- Security impact: The attacker can expand role/user data visibility by modifying authorization-model records in `sys_data_permission_ref`

### 1.2 Exploit path

Submit attacker-controlled `dataType`, `scopeType`, and `dataIds` to rewrite a target owner's data-permission references

### 1.3 Key code evidence

1. `DataPermissionRefController.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/DataPermissionRefController.java#L86
2. `DataPermissionRefController.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/DataPermissionRefController.java#L89
3. `DataPermissionRefServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/DataPermissionRefServiceImpl.java#L57
4. `DataScopeServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/DataScopeServiceImpl.java#L73

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Restore assignment permission checks, validate owner manageability, and enforce that assigned data ranges are within the grantor's own data scope

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/platform/issue1.html
