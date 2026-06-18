---
title: "platform issue5: Tenant DB Binding Can Be Read or Modified Without Authorization"
description: "platform has a missing authorization vulnerability in GET /tenants/{id}/db-ref, POST /tenants/{id}/db-binding. Reads or tampers with tenant-to-database binding, affecting tenant isolation and data-source selection"
tags:
  - platform
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

platform has a missing authorization vulnerability in GET /tenants/{id}/db-ref, POST /tenants/{id}/db-binding. Reads or tampers with tenant-to-database binding, affecting tenant isolation and data-source selection

- Attack precondition: The attacker is authenticated and knows tenant or DB instance IDs
- Affected endpoint: `GET /tenants/{id}/db-ref, POST /tenants/{id}/db-binding`
- Affected authorization property: `tenant:db-config, dbBinding, tenantId, id, @SaCheckPermission, TenantDbBinding`
- Security impact: Reads or tampers with tenant-to-database binding, affecting tenant isolation and data-source selection

### 1.2 Exploit path

Use `GET /tenants/{id}/db-ref` or `POST /tenants/{id}/db-binding`

### 1.3 Key code evidence

1. `TenantController.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/TenantController.java#L114
2. `TenantServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/TenantServiceImpl.java#L321
3. `TenantDbBindingSaveReq.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/TenantDbBindingSaveReq.java#L13
4. `DbInstanceMapper.xml`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/DbInstanceMapper.xml#L19

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Require `tenant:db-config`, force `tenantId` from the path, validate DB instance availability, and reuse the safer `saveSetting` pattern

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/platform/issue5.html
