---
title: "Spring-Cloud-Platform issue2: Missing Authorization in PUT /api/admin/group/{id}/authority/element/add, PUT /api/admin/group/{id}/authority/element/remove, POST /admin/group/{, PUT /group/{id}/authority/element/add, PUT /group/{id}/authority/element/remove, POST /admin/group/{*}/authority/element"
description: "Spring-Cloud-Platform has a missing authorization vulnerability in PUT /api/admin/group/{id}/authority/element/add, PUT /api/admin/group/{id}/authority/element/remove, POST /admin/group/{, PUT /group/{id}/authority/element/add, PUT /group/{id}/authority/element/remove, POST /admin/group/{*}/authority/element. An authenticated attacker can perform authorization-sensitive operations through PUT /api/admin/group/{id}/authority/element/add, PUT /api/admin/group/{id}/authority/element/remove, POST /admin/group/{, PUT /group/{id}/authority/element/add, PUT /group/{id}/authority/element/remove, POST /admin/group/{*}/authority/element without the required permission."
tags:
  - Spring-Cloud-Platform
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Spring-Cloud-Platform has a missing authorization vulnerability in PUT /api/admin/group/{id}/authority/element/add, PUT /api/admin/group/{id}/authority/element/remove, POST /admin/group/{, PUT /group/{id}/authority/element/add, PUT /group/{id}/authority/element/remove, POST /admin/group/{*}/authority/element. An authenticated attacker can perform authorization-sensitive operations through PUT /api/admin/group/{id}/authority/element/add, PUT /api/admin/group/{id}/authority/element/remove, POST /admin/group/{, PUT /group/{id}/authority/element/add, PUT /group/{id}/authority/element/remove, POST /admin/group/{*}/authority/element without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `PUT /api/admin/group/{id}/authority/element/add, PUT /api/admin/group/{id}/authority/element/remove, POST /admin/group/{, PUT /group/{id}/authority/element/add, PUT /group/{id}/authority/element/remove, POST /admin/group/{*}/authority/element`
- Affected authorization property: `groupId, elementId, PUT, base_resource_authority, ResourceAuthority, menuId`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through PUT /api/admin/group/{id}/authority/element/add, PUT /api/admin/group/{id}/authority/element/remove, POST /admin/group/{, PUT /group/{id}/authority/element/add, PUT /group/{id}/authority/element/remove, POST /admin/group/{*}/authority/element without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to PUT /api/admin/group/{id}/authority/element/add, PUT /api/admin/group/{id}/authority/element/remove, POST /admin/group/{, PUT /group/{id}/authority/element/add, PUT /group/{id}/authority/element/remove, POST /admin/group/{*}/authority/element with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `GroupController.java`

Evidence location: GroupController.java
2. `GroupBiz.java`

Evidence location: GroupBiz.java
3. `ElementMapper.xml`

Evidence location: ElementMapper.xml
4. `init.sql`

Evidence location: init.sql

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for PUT /api/admin/group/{id}/authority/element/add, PUT /api/admin/group/{id}/authority/element/remove, POST /admin/group/{, PUT /group/{id}/authority/element/add, PUT /group/{id}/authority/element/remove, POST /admin/group/{*}/authority/element before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Spring-Cloud-Platform/issue2.html
