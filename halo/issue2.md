---
title: "halo issue2: Public get-by-name hidden/approved"
description: "halo has a missing authorization vulnerability in GET /apis/api.halo.run/v1alpha1/comments/{name}, GET comments/{name}. An authenticated attacker can perform authorization-sensitive operations through GET /apis/api.halo.run/v1alpha1/comments/{name}, GET comments/{name} without the required permission."
tags:
  - halo
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

halo has a missing authorization vulnerability in GET /apis/api.halo.run/v1alpha1/comments/{name}, GET comments/{name}. An authenticated attacker can perform authorization-sensitive operations through GET /apis/api.halo.run/v1alpha1/comments/{name}, GET comments/{name} without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `GET /apis/api.halo.run/v1alpha1/comments/{name}, GET comments/{name}`
- Affected authorization property: `metadata.name, CommentFinderEndpoint.getComment, commentPublicQueryService.getByName(name), CommentPublicQueryServiceImpl.getByName, client.fetch(Comment.class, name), CommentVo.from(comment)`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through GET /apis/api.halo.run/v1alpha1/comments/{name}, GET comments/{name} without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to GET /apis/api.halo.run/v1alpha1/comments/{name}, GET comments/{name} with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `apis/api.halo.run`

Evidence location: https://github.com/halo-dev/halo/blob/master/apis/api.halo.run
2. `Comment.c`

Evidence location: https://github.com/halo-dev/halo/blob/master/Comment.c
3. `application/src/main/java/run/halo/app/core/endpoint/theme/CommentFinderEndpoint.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/application/src/main/java/run/halo/app/core/endpoint/theme/CommentFinderEndpoint.java
4. `application/src/main/java/run/halo/app/theme/finders/impl/CommentPublicQueryServiceImpl.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/application/src/main/java/run/halo/app/theme/finders/impl/CommentPublicQueryServiceImpl.java
5. `application/src/main/java/run/halo/app/theme/finders/vo/CommentVo.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/application/src/main/java/run/halo/app/theme/finders/vo/CommentVo.java
6. `api/src/main/java/run/halo/app/core/extension/content/Comment.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/api/src/main/java/run/halo/app/core/extension/content/Comment.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for GET /apis/api.halo.run/v1alpha1/comments/{name}, GET comments/{name} before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/halo/issue2.html
