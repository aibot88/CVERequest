---
title: "platform issue11: User orgId / positionId Can Be Written Without Manageable-Org Checks"
description: "platform has a missing authorization vulnerability: User orgId / positionId Can Be Written Without Manageable-Org Checks. `orgId` is used in data-scope calculation. Moving a user to a broader or different organization can change that user's later data visibility"
tags:
  - platform
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

platform has a missing authorization vulnerability: User orgId / positionId Can Be Written Without Manageable-Org Checks. `orgId` is used in data-scope calculation. Moving a user to a broader or different organization can change that user's later data visibility

- Attack precondition: The attacker has `sys:user:add` or `sys:user:edit` but should only manage a limited organization scope
- Security impact: `orgId` is used in data-scope calculation. Moving a user to a broader or different organization can change that user's later data visibility

### 1.2 Exploit path

Create or edit a user with attacker-controlled `orgId` / `positionId`

### 1.3 Key code evidence

1. `UserSaveReq.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/UserSaveReq.java#L58
2. `UserUpdateReq.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/UserUpdateReq.java#L46
3. `platform-admin/src/main/java/com/platform/controller/UserController.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/platform-admin/src/main/java/com/platform/controller/UserController.java#L88

```text
   85       */
   86      @RequestMapping("/delete")
   87      @RequiresPermissions("user:delete")
   88      public R delete(@RequestBody Integer[] ids) {
   89          userService.deleteBatch(ids);
   90  
   91          return R.ok();
   92      }
   93  
   94      /**
   95       * 查看所有列表
   96       */
   97      @RequestMapping("/queryAll")
   98      public R queryAll(@RequestParam Map<String, Object> params) {
   99  
  100          List<UserEntity> userList = userService.queryList(params);
  101  
  102          return R.ok().put("list", userList);
  103      }
  104  
```

4. `platform-admin/src/main/java/com/platform/service/impl/UserServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/platform-admin/src/main/java/com/platform/service/impl/UserServiceImpl.java#L107
5. `DataScopeServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/DataScopeServiceImpl.java#L73

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce manageable-org checks for `orgId` and `positionId`, and apply data-scope checks to the target user being modified

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/platform/issue11.html
