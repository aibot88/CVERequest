---
title: "RuoYi issue4: Unauthorized Role Assignment Deletion"
description: "RuoYi has a missing authorization vulnerability in /system/role/authUser/cancel, /system/role/authUser/cancelAll, roleId/userId(s). An authenticated attacker can perform authorization-sensitive operations through /system/role/authUser/cancel, /system/role/authUser/cancelAll, roleId/userId(s) without the required permission."
tags:
  - RuoYi
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

RuoYi has a missing authorization vulnerability in /system/role/authUser/cancel, /system/role/authUser/cancelAll, roleId/userId(s). An authenticated attacker can perform authorization-sensitive operations through /system/role/authUser/cancel, /system/role/authUser/cancelAll, roleId/userId(s) without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `/system/role/authUser/cancel, /system/role/authUser/cancelAll, roleId/userId(s)`
- Affected authorization property: ``sys_user_role.user_id`, `sys_user_role.role_id``
- Security impact: An authenticated attacker can perform authorization-sensitive operations through /system/role/authUser/cancel, /system/role/authUser/cancelAll, roleId/userId(s) without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to /system/role/authUser/cancel, /system/role/authUser/cancelAll, roleId/userId(s) with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java#L262

```text
  259      @Log(title = "[non-English text removed]", businessType = BusinessType.GRANT)
  260      @PostMapping("/authUser/cancel")
  261      @ResponseBody
  262      public AjaxResult cancelAuthUser(SysUserRole userRole)
  263      {
  264          return toAjax(roleService.deleteAuthUser(userRole));
  265      }
  266
  267      /**
  268       * [non-English text removed]
  269       */
  270      @RequiresPermissions("system:role:edit")
  271      @Log(title = "[non-English text removed]", businessType = BusinessType.GRANT)
  272      @PostMapping("/authUser/cancelAll")
  273      @ResponseBody
  274      public AjaxResult cancelAuthUserAll(Long roleId, String userIds)
  275      {
  276          return toAjax(roleService.deleteAuthUsers(roleId, userIds));
  277      }
  278
  279      /**
  280       * [non-English text removed]
  281       */
  282      @RequiresPermissions("system:role:list")
  283      @GetMapping("/authUser/selectUser/{roleId}")
```

2. `ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysRoleServiceImpl.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysRoleServiceImpl.java#L377

```text
  374      {
  375          return roleMapper.updateRole(role);
  376      }
  377
  378      /**
  379       * [non-English text removed]
  380       *
  381       * @param userRole [non-English text removed]
  382       * @return [non-English text removed]
  383       */
  384      @Override
  385      public int deleteAuthUser(SysUserRole userRole)
  386      {
  387          return userRoleMapper.deleteUserRoleInfo(userRole);
  388      }
  389
  390      /**
  391       * [non-English text removed]
  392       *
  393       * @param roleId [non-English text removed]ID
  394       * @param userIds [non-English text removed]ID
  395       * @return [non-English text removed]
```

3. `ruoyi-system/src/main/resources/mapper/system/SysUserRoleMapper.xml`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/resources/mapper/system/SysUserRoleMapper.xml#L38

```text
   35  		</foreach>
   36  	</insert>
   37
   38  	<delete id="deleteUserRoleInfo" parameterType="SysUserRole">
   39  		delete from sys_user_role where user_id=#{userId} and role_id=#{roleId}
   40  	</delete>
   41
   42  	<delete id="deleteUserRoleInfos">
   43  	    delete from sys_user_role where role_id=#{roleId} and user_id in
   44   	    <foreach collection="userIds" item="userId" open="(" separator="," close=")">
   45   	        #{userId}
   46              </foreach>
   47  	</delete>
   48  </mapper>
```

4. `roleService.c`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/roleService.c
5. `userService.c`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/userService.c

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for /system/role/authUser/cancel, /system/role/authUser/cancelAll, roleId/userId(s) before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/RuoYi/issue4.html
