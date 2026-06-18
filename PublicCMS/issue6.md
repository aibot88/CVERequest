---
title: "PublicCMS issue6: Department User Role Assignment Bypass"
description: "PublicCMS has a missing authorization vulnerability in `POST /admin/sysDept/saveUser`. A department manager can create or update a backend `superuser` with arbitrary roles, escalating beyond department-scoped administration"
tags:
  - PublicCMS
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

PublicCMS has a missing authorization vulnerability in `POST /admin/sysDept/saveUser`. A department manager can create or update a backend `superuser` with arbitrary roles, escalating beyond department-scoped administration

- Attack precondition: The attacker is a logged-in backend user with access to the “my department user add/edit” function and controls a department where `dept.userId == admin.id`
- Affected endpoint: ``POST /admin/sysDept/saveUser``
- Security impact: A department manager can create or update a backend `superuser` with arbitrary roles, escalating beyond department-scoped administration

### 1.2 Exploit path

Submit a department user save request with a department owned by the attacker and high-privilege `roleIds`

### 1.3 Key code evidence

1. `sysUser.c`

Evidence location: sysUser.c
2. `SysDeptAdminController.java`

Evidence location: SysDeptAdminController.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Do not accept arbitrary `roleIds` from this endpoint. Restrict assignable roles to a server-side allowlist or to roles explicitly grantable by the current admin, and avoid forcing `superuser=true` for department-managed users unless separately authorized

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/PublicCMS/issue6.html
