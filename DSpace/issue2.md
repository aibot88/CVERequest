---
title: "DSpace issue2: EPerson byEmail Search Leaks Account Authorization Properties"
description: "DSpace has a missing authorization vulnerability in GET /api/eperson/epersons/search/byEmail, GET /api/eperson/epersons/search/byEmail?email=, GET /api/eperson/epersons/search/byEmail?email=<target>. Unauthorized disclosure of EPerson account attributes including `email`, `netid`, `canLogIn`, `requireCertificate`, `selfRegistered`, and `lastActive`. These are authorization/authentication-related properties, especially `netid` and login flags"
tags:
  - DSpace
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

DSpace has a missing authorization vulnerability in GET /api/eperson/epersons/search/byEmail, GET /api/eperson/epersons/search/byEmail?email=, GET /api/eperson/epersons/search/byEmail?email=<target>. Unauthorized disclosure of EPerson account attributes including `email`, `netid`, `canLogIn`, `requireCertificate`, `selfRegistered`, and `lastActive`. These are authorization/authentication-related properties, especially `netid` and login flags

- Attack precondition: The attacker can call `GET /api/eperson/epersons/search/byEmail` and knows or guesses a target email address
- Affected endpoint: `GET /api/eperson/epersons/search/byEmail, GET /api/eperson/epersons/search/byEmail?email=, GET /api/eperson/epersons/search/byEmail?email=<target>`
- Affected authorization property: `findByEmail(), @PreAuthorize, EPersonRest, EPERSON READ, findOne, email`
- Security impact: Unauthorized disclosure of EPerson account attributes including `email`, `netid`, `canLogIn`, `requireCertificate`, `selfRegistered`, and `lastActive`. These are authorization/authentication-related properties, especially `netid` and login flags

### 1.2 Exploit path

`GET /api/eperson/epersons/search/byEmail?email=<target>` calls `findByEmail()` without method-level `@PreAuthorize`. The result is converted to `EPersonRest`, exposing account fields that normally require `EPERSON READ` via the direct `findOne` endpoint

### 1.3 Key code evidence

1. `EPersonRestRepository.java`

Evidence location: EPersonRestRepository.java
2. `EPersonConverter.java`

Evidence location: EPersonConverter.java
3. `EPersonRestPermissionEvaluatorPlugin.java`

Evidence location: EPersonRestPermissionEvaluatorPlugin.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add `@PreAuthorize("hasPermission(#email, 'EPERSON', 'READ')")` equivalent logic after resolving the target EPerson, or restrict `byEmail` to admin / self and return a minimized response for other users

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/DSpace/issue2.html
