---
title: "Ampache issue3: API `share_create` Arbitrary Target"
description: "Ampache has a missing authorization vulnerability in PUT /server/{json. The attacker can create a public share for an unauthorized target object. The resulting `share.secret` / `share.public_url` can be used to access the object through the share flow"
tags:
  - Ampache
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Ampache has a missing authorization vulnerability in PUT /server/{json. The attacker can create a public share for an unauthorized target object. The resulting `share.secret` / `share.public_url` can be used to access the object through the share flow

- Attack precondition: A low-privileged API user can call `share_create`, the `share` feature is enabled, and the attacker knows an existing object id they cannot access, such as another user's private playlist
- Affected endpoint: `PUT /server/{json`
- Affected authorization property: `share_create, share, share.secret, share.public_url, share.user, share.object_type`
- Security impact: The attacker can create a public share for an unauthorized target object. The resulting `share.secret` / `share.public_url` can be used to access the object through the share flow

### 1.2 Exploit path

`POST/PUT /server/{json,xml}.server.php?action=share_create|shares_create&type=playlist&filter={id}`

### 1.3 Key code evidence

1. `server.php`

Evidence location: server.php

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add a shared target authorization helper before `ShareCreator::create()`. For playlist / search targets, require public access or `has_access()` / `has_collaborate()` as appropriate; for media targets, enforce catalog / visibility rules

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Ampache/issue3.html
