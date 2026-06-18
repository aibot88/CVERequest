---
title: "Ampache issue1: API Direct Share Read"
description: "Ampache has a missing authorization vulnerability in POST /server/{json. The attacker can read another user's share `secret`, `public_url`, `object_type`, `object_id`, `allow_stream`, and `allow_download`. The `secret` and `public_url` are capability-style access credentials that can be used to consume the share"
tags:
  - Ampache
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Ampache has a missing authorization vulnerability in POST /server/{json. The attacker can read another user's share `secret`, `public_url`, `object_type`, `object_id`, `allow_stream`, and `allow_download`. The `secret` and `public_url` are capability-style access credentials that can be used to consume the share

- Attack precondition: A low-privileged user has valid API session / API ACL access, the `share` feature is enabled, and the attacker knows or guesses another user's `share_id`
- Affected endpoint: `POST /server/{json`
- Affected authorization property: `share, share_id, secret, public_url, object_type, object_id`
- Security impact: The attacker can read another user's share `secret`, `public_url`, `object_type`, `object_id`, `allow_stream`, and `allow_download`. The `secret` and `public_url` are capability-style access credentials that can be used to consume the share

### 1.2 Exploit path

`GET/POST /server/{json,xml}.server.php?action=share&filter={share_id}` directly serializes the requested share id

### 1.3 Key code evidence

1. `server.php`

Evidence location: server.php
2. `share.php`

Evidence location: share.php

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

In `Share8Method::share()` and version-equivalent methods, load the share by id and require `$share->isAccessible($user)` before serialization

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Ampache/issue1.html
