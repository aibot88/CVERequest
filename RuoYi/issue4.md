---
title: "RuoYi issue4: Unauthorized Role Assignment Deletion"
description: "RuoYi has a missing authorization vulnerability: Unauthorized Role Assignment Deletion. 越权撤销目标用户角色，导致权限被移除。"
tags:
  - RuoYi
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

RuoYi has a missing authorization vulnerability: Unauthorized Role Assignment Deletion. 越权撤销目标用户角色，导致权限被移除。

- Attack precondition: 拥有 `system:role:edit`。
- Affected authorization property: ``sys_user_role.user_id`, `sys_user_role.role_id`。`
- Security impact: 越权撤销目标用户角色，导致权限被移除。

### 1.2 Exploit path

POST `/system/role/authUser/cancel` 或 `/system/role/authUser/cancelAll`，提交任意 `roleId/userId(s)`。

### 1.3 Key code evidence

1. `ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java#L262

```text
  259      @Log(title = "角色管理", businessType = BusinessType.GRANT)
  260      @PostMapping("/authUser/cancel")
  261      @ResponseBody
  262      public AjaxResult cancelAuthUser(SysUserRole userRole)
  263      {
  264          return toAjax(roleService.deleteAuthUser(userRole));
  265      }
  266  
  267      /**
  268       * 批量取消授权
  269       */
  270      @RequiresPermissions("system:role:edit")
  271      @Log(title = "角色管理", businessType = BusinessType.GRANT)
  272      @PostMapping("/authUser/cancelAll")
  273      @ResponseBody
  274      public AjaxResult cancelAuthUserAll(Long roleId, String userIds)
  275      {
  276          return toAjax(roleService.deleteAuthUsers(roleId, userIds));
  277      }
  278  
  279      /**
  280       * 选择用户
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
  379       * 取消授权用户角色
  380       * 
  381       * @param userRole 用户和角色关联信息
  382       * @return 结果
  383       */
  384      @Override
  385      public int deleteAuthUser(SysUserRole userRole)
  386      {
  387          return userRoleMapper.deleteUserRoleInfo(userRole);
  388      }
  389  
  390      /**
  391       * 批量取消授权用户角色
  392       * 
  393       * @param roleId 角色ID
  394       * @param userIds 需要删除的用户数据ID
  395       * @return 结果
```

3. `ruoyi-system/target/classes/mapper/system/SysUserRoleMapper.xml`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/target/classes/mapper/system/SysUserRoleMapper.xml#L38

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

删除前调用 `roleService.checkRoleDataScope(roleId)` 和每个 `userService.checkUserDataScope(userId)`；操作后清理授权缓存。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/RuoYi/issue4.html
