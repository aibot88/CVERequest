---
title: "Ampache issue2: API Shares List"
description: "Ampache has a missing authorization vulnerability: API Shares List. The attacker can enumerate and retrieve other users' share `secret` and `public_url` values in bulk"
tags:
  - Ampache
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Ampache has a missing authorization vulnerability: API Shares List. The attacker can enumerate and retrieve other users' share `secret` and `public_url` values in bulk

- Attack precondition: A low-privileged user has valid API session / API ACL access, the `share` feature is enabled, and other users have existing share rows
- Security impact: The attacker can enumerate and retrieve other users' share `secret` and `public_url` values in bulk

### 1.2 Exploit path

`GET/POST /server/{json,xml}.server.php?action=shares` uses Browse type `share` and returns serialized share rows

### 1.3 Key code evidence

1. `server.php`

Evidence location: server.php

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Use `ShareRepository::getIdsByUser($user)` for the list source, or add equivalent owner / manager filtering in the share Browse query

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Ampache/issue2.html
