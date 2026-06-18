---
title: "Ampache issue4: Web Share Create / External Share Arbitrary Target"
description: "Ampache has a missing authorization vulnerability: Web Share Create / External Share Arbitrary Target. The attacker can create a public share for an object they cannot otherwise access"
tags:
  - Ampache
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Ampache has a missing authorization vulnerability: Web Share Create / External Share Arbitrary Target. The attacker can create a public share for an object they cannot otherwise access

- Attack precondition: - For `create`: a logged-in web user can obtain a valid `add_share` form token
- Security impact: The attacker can create a public share for an object they cannot otherwise access

### 1.2 Exploit path

- `GET /share.php?action=show_create&type={type}&id={id}` to obtain form context / token

### 1.3 Key code evidence

1. `share.php`

Evidence location: share.php
2. `public/share.php`

Evidence location: public/share.php

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Before creating a share in `CreateAction` and `ExternalShareAction`, load the target object and enforce the same target authorization helper recommended for API `share_create`

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Ampache/issue4.html
