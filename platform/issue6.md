---
title: "platform issue6: DB Instance Configuration Can Be Modified Without Authorization"
description: "platform has a missing authorization vulnerability in POST /db-instances/create, PUT /db-instances/{id}/modify, DELETE /db-instances/{id}. Persistent tampering with data-source configuration can alter tenant data isolation targets or break availability"
tags:
  - platform
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

platform has a missing authorization vulnerability in POST /db-instances/create, PUT /db-instances/{id}/modify, DELETE /db-instances/{id}. Persistent tampering with data-source configuration can alter tenant data isolation targets or break availability

- Attack precondition: The attacker is authenticated; the modified DB instance is bound, or may later be bound, to a tenant
- Affected endpoint: `POST /db-instances/create, PUT /db-instances/{id}/modify, DELETE /db-instances/{id}`
- Affected authorization property: `tenant:db-config, @SaCheckPermission`
- Security impact: Persistent tampering with data-source configuration can alter tenant data isolation targets or break availability

### 1.2 Exploit path

Use `POST /db-instances/create`, `PUT /db-instances/{id}/modify`, or `DELETE /db-instances/{id}`

### 1.3 Key code evidence

1. `DbInstanceController.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/DbInstanceController.java#L70
2. `DbInstanceServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/DbInstanceServiceImpl.java#L90
3. `DbInstanceServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/DbInstanceServiceImpl.java#L113
4. `DbInstanceMapper.xml`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/DbInstanceMapper.xml#L6

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Require `tenant:db-config`, block unsafe modification/deletion of bound instances, and validate all binding relationships before applying changes

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/platform/issue6.html
