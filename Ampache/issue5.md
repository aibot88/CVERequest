---
title: "Ampache issue5: Playlist Source Object Authorization Bypass"
description: "Ampache has a missing authorization vulnerability: Playlist Source Object Authorization Bypass. The attacker can bind unauthorized source content into their own playlist. That playlist can later be read, played, or shared through flows that trust `playlist_data`"
tags:
  - Ampache
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Ampache has a missing authorization vulnerability: Playlist Source Object Authorization Bypass. The attacker can bind unauthorized source content into their own playlist. That playlist can later be read, played, or shared through flows that trust `playlist_data`

- Attack precondition: A low-privileged API user can modify a playlist they own or collaborate on, and knows a source object id they cannot access, such as another user's private playlist
- Security impact: The attacker can bind unauthorized source content into their own playlist. That playlist can later be read, played, or shared through flows that trust `playlist_data`

### 1.2 Exploit path

- `playlist_add` checks write access to the destination playlist

### 1.3 Key code evidence

No concrete source path was extracted automatically. Review the issue body and source tree before final CVE submission.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Authorize both sides of the relationship. Require source playlist / search access before expansion, and require media / catalog visibility before writing `playlist_data`

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Ampache/issue5.html
