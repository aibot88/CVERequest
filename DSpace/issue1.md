---
title: "DSpace issue1: Relationship Creation Allows Unauthorized Author/Profile Binding"
description: "DSpace has a missing authorization vulnerability. Unauthorized `READ` access to another in-progress item through forged author/profile relationship metadata"
tags:
  - DSpace
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

DSpace has a missing authorization vulnerability. Unauthorized `READ` access to another in-progress item through forged author/profile relationship metadata

- Attack precondition: The attacker is an authenticated user who can write their own Person/Profile item. Researcher profile / shared workspace author metadata support is enabled
- Affected authorization property: `WRITE, dc.contributor.author, READ, leftItem WRITE || rightItem WRITE, relationshipDAO.create, researcherProfileService.isAuthorOf(...)`
- Security impact: Unauthorized `READ` access to another in-progress item through forged author/profile relationship metadata

### 1.2 Exploit path

The attacker creates a relationship between their writable profile/person item and another in-progress publication item. Relationship creation accepts `WRITE` permission on either side, so the attacker does not need `WRITE` on the target publication item. The resulting author relationship can populate `dc.contributor.author`, and later permission logic treats the matching profile authority as an author-based `READ` grant

### 1.3 Key code evidence

1. `dc.c`

Evidence location: dc.c
2. `RelationshipRestRepository.java`

Evidence location: RelationshipRestRepository.java
3. `RelationshipServiceImpl.java`

Evidence location: RelationshipServiceImpl.java
4. `relationshipDAO.c`

Evidence location: relationshipDAO.c
5. `AuthorizeServicePermissionEvaluatorPlugin.java`

Evidence location: AuthorizeServicePermissionEvaluatorPlugin.java
6. `ResearcherProfileServiceImpl.java`

Evidence location: ResearcherProfileServiceImpl.java
7. `discovery.xml`

Evidence location: discovery.xml
8. `virtual-metadata.xml`

Evidence location: virtual-metadata.xml

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Require authorization over both relationship endpoints for authorization-sensitive relationship types, or add a specific policy check that verifies the current user may assign the chosen profile/person as an author of the target item

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/DSpace/issue1.html
