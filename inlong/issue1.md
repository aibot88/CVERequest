---
title: "inlong issue1: C-1: Cross-tenant tenant-role assignment"
description: "inlong has a missing authorization vulnerability in /api/role/tenant/save, /api/role/tenant/update, /api/role/tenant/delete. The attacker can create, modify, or delete tenant-role bindings outside the tenant they administer, breaking tenant RBAC boundaries"
tags:
  - inlong
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

inlong has a missing authorization vulnerability in /api/role/tenant/save, /api/role/tenant/update, /api/role/tenant/delete. The attacker can create, modify, or delete tenant-role bindings outside the tenant they administer, breaking tenant RBAC boundaries

- Attack precondition: The attacker is authenticated and has `TENANT_ADMIN` in any tenant, or has another role that can reach the tenant-role write endpoints
- Affected endpoint: `/api/role/tenant/save, /api/role/tenant/update, /api/role/tenant/delete`
- Affected authorization property: `TENANT_ADMIN, tenant, username, roleCode, INLONG_ADMIN, tenant_user_role`
- Security impact: The attacker can create, modify, or delete tenant-role bindings outside the tenant they administer, breaking tenant RBAC boundaries

### 1.2 Exploit path

Call `/api/role/tenant/save`, `/api/role/tenant/update`, or `/api/role/tenant/delete` with a target `tenant`, `username`, and `roleCode` in the request body or path

### 1.3 Key code evidence

1. `inlong-manager/manager-web/src/main/java/org/apache/inlong/manager/web/controller/InlongTenantRoleController.java`

Evidence location: inlong-manager/manager-web/src/main/java/org/apache/inlong/manager/web/controller/InlongTenantRoleController.java
2. `inlong-manager/manager-web/src/main/java/org/apache/inlong/manager/web/controller/openapi/OpenInlongTenantRoleController.java`

Evidence location: inlong-manager/manager-web/src/main/java/org/apache/inlong/manager/web/controller/openapi/OpenInlongTenantRoleController.java
3. `inlong-manager/manager-service/src/main/java/org/apache/inlong/manager/service/user/TenantRoleServiceImpl.java`

Evidence location: inlong-manager/manager-service/src/main/java/org/apache/inlong/manager/service/user/TenantRoleServiceImpl.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Before save/update/delete, check `operator` has admin permission for the target tenant. For update/delete-by-id, load the existing role record first and validate permission on its tenant. Keep `INLONG_ADMIN` as an explicit global exception if intended

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/inlong/issue1.html
