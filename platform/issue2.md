---
title: "platform issue2: Data Permission Model Readable Without Authorization"
description: "platform has a missing authorization vulnerability in GET /data-permissions/{ownerType}/{ownerId}, ownerType/ownerId. Leaks data authorization configuration, including `dataType`, `scopeType`, and `dataIds`"
tags:
  - platform
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

platform has a missing authorization vulnerability in GET /data-permissions/{ownerType}/{ownerId}, ownerType/ownerId. Leaks data authorization configuration, including `dataType`, `scopeType`, and `dataIds`

- Attack precondition: The attacker is authenticated and knows or can guess `ownerType/ownerId`
- Affected endpoint: `GET /data-permissions/{ownerType}/{ownerId}, ownerType/ownerId`
- Affected authorization property: `dataType, scopeType, dataIds, DataPermissionRef, sys:data-permission:read`
- Security impact: Leaks data authorization configuration, including `dataType`, `scopeType`, and `dataIds`

### 1.2 Exploit path

Call `GET /data-permissions/{ownerType}/{ownerId}` to retrieve authorization-model fields

### 1.3 Key code evidence

1. `DataPermissionRefController.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/DataPermissionRefController.java#L56
2. `DataPermissionResp.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/DataPermissionResp.java#L35

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add a read permission such as `sys:data-permission:read` and restrict readable owners to the current user's manageable scope

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/platform/issue2.html
