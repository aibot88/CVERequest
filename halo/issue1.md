---
title: "halo issue1: 任意角色授予 / `super-role` 提权"
description: "halo has a missing authorization vulnerability: 任意角色授予 / `super-role` 提权. 攻击者可将默认存在的 `super-role` 授予自己、新建用户或任意目标用户，从而获得全局 `*` 权限，实现权限提升。"
tags:
  - halo
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

halo has a missing authorization vulnerability: 任意角色授予 / `super-role` 提权. 攻击者可将默认存在的 `super-role` 授予自己、新建用户或任意目标用户，从而获得全局 `*` 权限，实现权限提升。

- Security impact: 攻击者可将默认存在的 `super-role` 授予自己、新建用户或任意目标用户，从而获得全局 `*` 权限，实现权限提升。

### 1.2 Exploit path

1. 攻击者提交请求体，例如 `roles: ["super-role"]`。 2. `UserEndpoint.createUser` 或 `UserEndpoint.grantPermission` 将请求中的 roles 传入用户服务。 3. `UserServiceImpl.createUser` 只校验 role 是否存在。 4. `UserServiceImpl.grantRoles` 调用 `RoleBinding.create(username, role)`。 5. `RoleBinding.create` 将 role 写入 `roleRef.name`，将目标用户写入 `subjects.name`。 6. 后续认证和授权流程读取 `RoleBinding`，目标用户获得 `ROLE_super-role`。

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
9. `application/build/resources/main/extensions/system-default-role.yaml`

Evidence location: https://github.com/halo-dev/halo/blob/master/application/build/resources/main/extensions/system-default-role.yaml
10. `application/src/main/java/run/halo/app/core/user/service/impl/PatServiceImpl.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/application/src/main/java/run/halo/app/core/user/service/impl/PatServiceImpl.java

## 2. Existing checks and why they fail

- 路由级 RBAC 只说明调用者可以访问授予权限接口。
- `createUser` 只检查 role 是否存在，不能阻止授予高权限 role。
- `grantRoles` 不比较 requested roles 与 current user roles。
- 未发现 `super-role` / system-reserved role 的授予限制。

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

在 `grantRoles` / `createUser` 中增加角色支配检查：`requested roles <= caller roles`。 - 禁止非 `super-role` 用户授予 `super-role` 或 system-reserved role。 - 复用或抽象 PAT 创建路径中的 `hasSufficientRoles` 检查逻辑。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/halo/issue1.html
