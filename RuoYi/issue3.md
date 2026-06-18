---
title: "RuoYi issue3: Unauthorized Role Assignment To Users"
description: "RuoYi has a missing authorization vulnerability: Unauthorized Role Assignment To Users. 给不可见用户授予角色，改变其 RBAC membership 和后续权限集合。"
tags:
  - RuoYi
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

RuoYi has a missing authorization vulnerability: Unauthorized Role Assignment To Users. 给不可见用户授予角色，改变其 RBAC membership 和后续权限集合。

- Attack precondition: 拥有 `system:role:edit`，且目标 `roleId` 可见。
- Affected authorization property: ``sys_user_role.user_id`, `sys_user_role.role_id`。`
- Security impact: 给不可见用户授予角色，改变其 RBAC membership 和后续权限集合。

### 1.2 Exploit path

POST `/system/role/authUser/selectAll`，提交不在操作者 DataScope 内的 `userIds`。

### 1.3 Key code evidence

1. `ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java#L310

```text
  307      @Log(title = "角色管理", businessType = BusinessType.GRANT)
  308      @PostMapping("/authUser/selectAll")
  309      @ResponseBody
  310      public AjaxResult selectAuthUserAll(Long roleId, String userIds)
  311      {
  312          roleService.checkRoleDataScope(roleId);
  313          return toAjax(roleService.insertAuthUsers(roleId, userIds));
  314      }
  315  
  316      /**
  317       * 加载角色部门（数据权限）列表树
  318       */
  319      @RequiresPermissions("system:role:edit")
  320      @GetMapping("/deptTreeData")
```

2. `ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysRoleServiceImpl.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysRoleServiceImpl.java#L403

```text
  400          return userRoleMapper.deleteUserRoleInfos(roleId, Convert.toLongArray(userIds));
  401      }
  402  
  403      /**
  404       * 批量选择授权用户角色
  405       * 
  406       * @param roleId 角色ID
  407       * @param userIds 需要授权的用户数据ID
  408       * @return 结果
  409       */
  410      @Override
  411      public int insertAuthUsers(Long roleId, String userIds)
  412      {
  413          Long[] users = Convert.toLongArray(userIds);
  414          // 新增用户与角色管理
  415          List<SysUserRole> list = new ArrayList<SysUserRole>();
  416          for (Long userId : users)
  417          {
  418              SysUserRole ur = new SysUserRole();
```

3. `ruoyi-system/target/classes/mapper/system/SysUserRoleMapper.xml`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/target/classes/mapper/system/SysUserRoleMapper.xml#L31

```text
   28          </foreach> 
   29   	</delete>
   30  	
   31  	<insert id="batchUserRole">
   32  		insert into sys_user_role(user_id, role_id) values
   33  		<foreach item="item" index="index" collection="list" separator=",">
   34  			(#{item.userId},#{item.roleId})
   35  		</foreach>
   36  	</insert>
   37  	
   38  	<delete id="deleteUserRoleInfo" parameterType="SysUserRole">
```

4. `ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysUserServiceImpl.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysUserServiceImpl.java#L456

```text
  453       * @param userId 用户id
  454       */
  455      @Override
  456      public void checkUserDataScope(Long userId)
  457      {
  458          if (!ShiroUtils.isAdmin())
  459          {
  460              SysUser user = new SysUser();
  461              user.setUserId(userId);
  462              List<SysUser> users = SpringUtils.getAopProxy(this).selectUserList(user);
  463              if (StringUtils.isEmpty(users))
  464              {
  465                  throw new ServiceException("没有权限访问用户数据！");
  466              }
  467          }
  468      }
  469  
  470      /**
```

5. `userService.c`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/userService.c

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

对每个待授权 `userId` 调用 `userService.checkUserDataScope(userId)`，并禁止对超级管理员用户进行授权变更。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/RuoYi/issue3.html
