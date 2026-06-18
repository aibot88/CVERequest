---
title: "Spring-Cloud-Platform issue6: group-user"
description: "Spring-Cloud-Platform has a missing authorization vulnerability in GET /api/admin/group/{id}/user, PUT /admin/group/{, GET /admin/group/{, GET /group/{id}/user, PUT /admin/group/{*}/user, GET /admin/group/{*}. An authenticated attacker can perform authorization-sensitive operations through GET /api/admin/group/{id}/user, PUT /admin/group/{, GET /admin/group/{, GET /group/{id}/user, PUT /admin/group/{*}/user, GET /admin/group/{*} without the required permission."
tags:
  - Spring-Cloud-Platform
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Spring-Cloud-Platform has a missing authorization vulnerability in GET /api/admin/group/{id}/user, PUT /admin/group/{, GET /admin/group/{, GET /group/{id}/user, PUT /admin/group/{*}/user, GET /admin/group/{*}. An authenticated attacker can perform authorization-sensitive operations through GET /api/admin/group/{id}/user, PUT /admin/group/{, GET /admin/group/{, GET /group/{id}/user, PUT /admin/group/{*}/user, GET /admin/group/{*} without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `GET /api/admin/group/{id}/user, PUT /admin/group/{, GET /admin/group/{, GET /group/{id}/user, PUT /admin/group/{*}/user, GET /admin/group/{*}`
- Affected authorization property: `GroupUsers, base_user u.*, password, getGroupUsers, select u.*, client.*`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through GET /api/admin/group/{id}/user, PUT /admin/group/{, GET /admin/group/{, GET /group/{id}/user, PUT /admin/group/{*}/user, GET /admin/group/{*} without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to GET /api/admin/group/{id}/user, PUT /admin/group/{, GET /admin/group/{, GET /group/{id}/user, PUT /admin/group/{*}/user, GET /admin/group/{*} with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `GroupController.java`

Evidence location: GroupController.java
2. `GroupBiz.java`

Evidence location: GroupBiz.java
3. `UserMapper.xml`

Evidence location: UserMapper.xml
4. `MenuMapper.xml`

Evidence location: MenuMapper.xml
5. `ElementMapper.xml`

Evidence location: ElementMapper.xml

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for GET /api/admin/group/{id}/user, PUT /admin/group/{, GET /admin/group/{, GET /group/{id}/user, PUT /admin/group/{*}/user, GET /admin/group/{*} before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Spring-Cloud-Platform/issue6.html
