---
title: "halo issue1: / `super-role`"
description: "halo has a missing authorization vulnerability in POST /apis/api.console.halo.run/v1alpha1/users, POST /apis/api.console.halo.run/v1alpha1/users/{name}/permissions, apiGroups/resources/nonResourceURLs/verbs, /users/{name}/permissions. An authenticated attacker can perform authorization-sensitive operations through POST /apis/api.console.halo.run/v1alpha1/users, POST /apis/api.console.halo.run/v1alpha1/users/{name}/permissions, apiGroups/resources/nonResourceURLs/verbs, /users/{name}/permissions without the required permission."
tags:
  - halo
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

halo has a missing authorization vulnerability in POST /apis/api.console.halo.run/v1alpha1/users, POST /apis/api.console.halo.run/v1alpha1/users/{name}/permissions, apiGroups/resources/nonResourceURLs/verbs, /users/{name}/permissions. An authenticated attacker can perform authorization-sensitive operations through POST /apis/api.console.halo.run/v1alpha1/users, POST /apis/api.console.halo.run/v1alpha1/users/{name}/permissions, apiGroups/resources/nonResourceURLs/verbs, /users/{name}/permissions without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `POST /apis/api.console.halo.run/v1alpha1/users, POST /apis/api.console.halo.run/v1alpha1/users/{name}/permissions, apiGroups/resources/nonResourceURLs/verbs, /users/{name}/permissions`
- Affected authorization property: `super-role, role-template-manage-users, role-template-manage-permissions, roles: ["super-role"], UserEndpoint.createUser, UserEndpoint.grantPermission`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through POST /apis/api.console.halo.run/v1alpha1/users, POST /apis/api.console.halo.run/v1alpha1/users/{name}/permissions, apiGroups/resources/nonResourceURLs/verbs, /users/{name}/permissions without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to POST /apis/api.console.halo.run/v1alpha1/users, POST /apis/api.console.halo.run/v1alpha1/users/{name}/permissions, apiGroups/resources/nonResourceURLs/verbs, /users/{name}/permissions with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `apis/api.console.halo.run`

Evidence location: https://github.com/halo-dev/halo/blob/master/apis/api.console.halo.run
2. `UserEndpoint.c`

Evidence location: https://github.com/halo-dev/halo/blob/master/UserEndpoint.c
3. `UserServiceImpl.c`

Evidence location: https://github.com/halo-dev/halo/blob/master/UserServiceImpl.c
4. `RoleBinding.c`

Evidence location: https://github.com/halo-dev/halo/blob/master/RoleBinding.c
5. `application/src/main/java/run/halo/app/core/endpoint/console/UserEndpoint.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/application/src/main/java/run/halo/app/core/endpoint/console/UserEndpoint.java
6. `userService.c`

Evidence location: https://github.com/halo-dev/halo/blob/master/userService.c
7. `application/src/main/java/run/halo/app/core/user/service/impl/UserServiceImpl.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/application/src/main/java/run/halo/app/core/user/service/impl/UserServiceImpl.java
8. `api/src/main/java/run/halo/app/core/extension/RoleBinding.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/api/src/main/java/run/halo/app/core/extension/RoleBinding.java
9. `application/src/main/resources/extensions/system-default-role.yaml`

Evidence location: https://github.com/halo-dev/halo/blob/master/application/src/main/resources/extensions/system-default-role.yaml
10. `application/src/main/java/run/halo/app/core/user/service/impl/PatServiceImpl.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/application/src/main/java/run/halo/app/core/user/service/impl/PatServiceImpl.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for POST /apis/api.console.halo.run/v1alpha1/users, POST /apis/api.console.halo.run/v1alpha1/users/{name}/permissions, apiGroups/resources/nonResourceURLs/verbs, /users/{name}/permissions before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/halo/issue1.html
