---
title: "PublicCMS issue3: Department Resource Authorization Expansion"
description: "PublicCMS has a missing authorization vulnerability in `POST /admin/sysDept/save`. Users in that department can gain access to categories, pages, or config resources outside the actor's intended management scope"
tags:
  - PublicCMS
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

PublicCMS has a missing authorization vulnerability in `POST /admin/sysDept/save`. Users in that department can gain access to categories, pages, or config resources outside the actor's intended management scope

- Attack precondition: The attacker is a logged-in backend administrator with access to department save functionality
- Affected endpoint: ``POST /admin/sysDept/save``
- Security impact: Users in that department can gain access to categories, pages, or config resources outside the actor's intended management scope

### 1.2 Exploit path

Submit department save data that sets broad `ownsAll*` flags or binds arbitrary `categoryIds`, `pages`, or `configs` to a department

### 1.3 Key code evidence

1. `SysDeptAdminController.java`

Evidence location: SysDeptAdminController.java
2. `SysDeptItemService.java`

Evidence location: SysDeptItemService.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Before saving department resource bindings, validate every target category/page/config against the acting admin's manageable resources. Restrict `ownsAll*` flags to full administrators

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/PublicCMS/issue3.html
