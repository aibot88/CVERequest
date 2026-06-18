---
title: "RuoYi issue3: Unauthorized Role Assignment To Users"
description: "RuoYi has a missing authorization vulnerability in /system/role/authUser/selectAll, allocatedList/unallocatedList. An authenticated attacker can perform authorization-sensitive operations through /system/role/authUser/selectAll, allocatedList/unallocatedList without the required permission."
tags:
  - RuoYi
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

RuoYi has a missing authorization vulnerability in /system/role/authUser/selectAll, allocatedList/unallocatedList. An authenticated attacker can perform authorization-sensitive operations through /system/role/authUser/selectAll, allocatedList/unallocatedList without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `/system/role/authUser/selectAll, allocatedList/unallocatedList`
- Affected authorization property: ``sys_user_role.user_id`, `sys_user_role.role_id``
- Security impact: An authenticated attacker can perform authorization-sensitive operations through /system/role/authUser/selectAll, allocatedList/unallocatedList without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to /system/role/authUser/selectAll, allocatedList/unallocatedList with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java#L310

```text
  307      @Log(title = "[non-English text removed]", businessType = BusinessType.GRANT)
  308      @PostMapping("/authUser/selectAll")
  309      @ResponseBody
  310      public AjaxResult selectAuthUserAll(Long roleId, String userIds)
  311      {
  312          roleService.checkRoleDataScope(roleId);
  313          return toAjax(roleService.insertAuthUsers(roleId, userIds));
  314      }
  315
  316      /**
  317       * [non-English text removed]([non-English text removed])[non-English text removed]
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
  404       * [non-English text removed]
  405       *
  406       * @param roleId [non-English text removed]ID
  407       * @param userIds [non-English text removed]ID
  408       * @return [non-English text removed]
  409       */
  410      @Override
  411      public int insertAuthUsers(Long roleId, String userIds)
  412      {
  413          Long[] users = Convert.toLongArray(userIds);
  414          // [non-English text removed]
  415          List<SysUserRole> list = new ArrayList<SysUserRole>();
  416          for (Long userId : users)
  417          {
  418              SysUserRole ur = new SysUserRole();
```

3. `ruoyi-system/src/main/resources/mapper/system/SysUserRoleMapper.xml`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/resources/mapper/system/SysUserRoleMapper.xml#L31

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
  453       * @param userId [non-English text removed]id
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
  465                  throw new ServiceException("[non-English text removed]");
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

Enforce server-side authorization for /system/role/authUser/selectAll, allocatedList/unallocatedList before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/RuoYi/issue3.html
