---
title: "JEEWMS issue1: `saveUser` 可重建用户角色和组织绑定"
description: "JEEWMS has a missing authorization vulnerability: `saveUser` 可重建用户角色和组织绑定. 可将任意用户加入更高权限角色或跨组织绑定，改变系统后续菜单、接口、数据权限判断结果。"
tags:
  - JEEWMS
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JEEWMS has a missing authorization vulnerability: `saveUser` 可重建用户角色和组织绑定. 可将任意用户加入更高权限角色或跨组织绑定，改变系统后续菜单、接口、数据权限判断结果。

- Attack precondition: 攻击者能访问 `userController.do?saveUser`。不要求攻击者已拥有目标角色或目标组织的管理权限。
- Security impact: 可将任意用户加入更高权限角色或跨组织绑定，改变系统后续菜单、接口、数据权限判断结果。

### 1.2 Exploit path

请求中提交目标用户 `id`、`roleid`、`orgIds` 等参数，触发用户更新逻辑删除旧绑定并重建用户-角色、用户-组织关系。

### 1.3 Key code evidence

1. `src/main/java/org/jeecgframework/web/system/controller/core/UserController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/UserController.java#L581

```text
  578       * @return
  579       */
  580  
  581      @RequestMapping(params = "saveUser")
  582      @ResponseBody
  583      public AjaxJson saveUser(HttpServletRequest req, TSUser user) {
  584          String message = null;
```

2. `jeewms-cloud/java/base-cloud-module/base-cloud-xxljob/src/main/java/com/xxl/job/admin/controller/UserController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/jeewms-cloud/java/base-cloud-module/base-cloud-xxljob/src/main/java/com/xxl/job/admin/controller/UserController.java#L587
3. `jeewms-cloud/java/base-cloud-module/base-cloud-xxljob/src/main/java/com/xxl/job/admin/controller/UserController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/jeewms-cloud/java/base-cloud-module/base-cloud-xxljob/src/main/java/com/xxl/job/admin/controller/UserController.java#L595
4. `jeewms-cloud/java/base-cloud-module/base-cloud-xxljob/src/main/java/com/xxl/job/admin/controller/UserController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/jeewms-cloud/java/base-cloud-module/base-cloud-xxljob/src/main/java/com/xxl/job/admin/controller/UserController.java#L643
5. `jeewms-cloud/java/base-cloud-module/base-cloud-xxljob/src/main/java/com/xxl/job/admin/controller/UserController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/jeewms-cloud/java/base-cloud-module/base-cloud-xxljob/src/main/java/com/xxl/job/admin/controller/UserController.java#L664

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

在保存前校验当前用户是否可管理目标用户、目标组织和目标角色；禁止授予高于当前用户权限上界的角色；服务端忽略或白名单化敏感关系字段。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JEEWMS/issue1.html
