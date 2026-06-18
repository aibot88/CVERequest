---
title: "pig issue4: OAuth Client Secret and Authorization Config Disclosure"
description: "pig has a missing authorization vulnerability in - `GET /client/{clientId}`. Disclosure of OAuth client secrets can enable client impersonation or facilitate attacks against token issuance flows, depending on deployed OAuth clients and grant types"
tags:
  - pig
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

pig has a missing authorization vulnerability in - `GET /client/{clientId}`. Disclosure of OAuth client secrets can enable client impersonation or facilitate attacks against token issuance flows, depending on deployed OAuth clients and grant types

- Attack precondition: Any authenticated user
- Affected endpoint: `- `GET /client/{clientId}``
- Affected authorization property: `clientSecret, scope, authorizedGrantTypes, autoapprove, sys_client_view, SysOauthClientDetails`
- Security impact: Disclosure of OAuth client secrets can enable client impersonation or facilitate attacks against token issuance flows, depending on deployed OAuth clients and grant types

### 1.2 Exploit path

1. Authenticated user calls `/client/{clientId}` or `/client/export`. 2. The endpoint returns `SysOauthClientDetails` or DTO data containing `clientSecret` and OAuth grant configuration. 3. The attacker can use leaked client credentials/configuration in OAuth flows

### 1.3 Key code evidence

1. `SysClientController.java`

Evidence location: SysClientController.java
2. `SysOauthClientDetails.java`

Evidence location: SysOauthClientDetails.java
3. `PigRemoteRegisteredClientRepository.java`

Evidence location: PigRemoteRegisteredClientRepository.java

## 2. Existing checks and why they fail

- `/client/page` has `sys_client_view`, but `/client/{clientId}` and `/client/export` do not. - The entity/DTO does not mask or omit `clientSecret`

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add `@HasPermission("sys_client_view")` to all client read/export endpoints. - Never return raw `clientSecret` to frontend/API callers; use masked output by default. - Expose raw secret only through a tightly controlled administrative rotation/reveal flow

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/pig/issue4.html
