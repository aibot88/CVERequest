---
title: "RuoYi issue1: Role Menu Permission Overwrite"
description: "RuoYi has a missing authorization vulnerability in /system/role/add, /system/role/edit, system:role:add/edit. An authenticated attacker can perform authorization-sensitive operations through /system/role/add, /system/role/edit, system:role:add/edit without the required permission."
tags:
  - RuoYi
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

RuoYi has a missing authorization vulnerability in /system/role/add, /system/role/edit, system:role:add/edit. An authenticated attacker can perform authorization-sensitive operations through /system/role/add, /system/role/edit, system:role:add/edit without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `/system/role/add, /system/role/edit, system:role:add/edit`
- Affected authorization property: ``sys_role_menu.role_id`, `sys_role_menu.menu_id`, `SysRole.menuIds``
- Security impact: An authenticated attacker can perform authorization-sensitive operations through /system/role/add, /system/role/edit, system:role:add/edit without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to /system/role/add, /system/role/edit, system:role:add/edit with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java#L95

```text
   92      @PostMapping("/add")
   93      @ResponseBody
   94      public AjaxResult addSave(@Validated SysRole role)
   95      {
   96          if (!roleService.checkRoleNameUnique(role))
   97          {
   98              return error("[non-English text removed]'" + role.getRoleName() + "'[non-English text removed],[non-English text removed]");
   99          }
  100          else if (!roleService.checkRoleKeyUnique(role))
  101          {
  102              return error("[non-English text removed]'" + role.getRoleName() + "'[non-English text removed],[non-English text removed]");
  103          }
  104          role.setCreateBy(getLoginName());
  105          AuthorizationUtils.clearAllCachedAuthorizationInfo();
  106          return toAjax(roleService.insertRole(role));
  107
  108      }
  109
  110      /**
  111       * [non-English text removed]
  112       */
  113      @RequiresPermissions("system:role:edit")
  114      @GetMapping("/edit/{roleId}")
```

2. `ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysRoleServiceImpl.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysRoleServiceImpl.java#L198

```text
  195       * @param role [non-English text removed]
  196       * @return [non-English text removed]
  197       */
  198      @Override
  199      @Transactional
  200      public int updateRole(SysRole role)
  201      {
  202          // [non-English text removed]
  203          roleMapper.updateRole(role);
  204          // [non-English text removed]
  205          roleMenuMapper.deleteRoleMenuByRoleId(role.getRoleId());
  206          return insertRoleMenu(role);
  207      }
```

3. `ruoyi-system/src/main/resources/mapper/system/SysRoleMenuMapper.xml`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/resources/mapper/system/SysRoleMenuMapper.xml#L27

```text
   24          </foreach>
   25   	</delete>
   26
   27  	<insert id="batchRoleMenu">
   28  		insert into sys_role_menu(role_id, menu_id) values
   29  		<foreach item="item" index="index" collection="list" separator=",">
   30  			(#{item.roleId},#{item.menuId})
   31  		</foreach>
   32  	</insert>
   33
   34  </mapper>
```

4. `ruoyi-system/src/main/resources/mapper/system/SysMenuMapper.xml`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/resources/mapper/system/SysMenuMapper.xml#L64

```text
   61  		order by m.parent_id, m.order_num
   62  	</select>
   63
   64  	<select id="selectPermsByUserId" parameterType="Long" resultType="String">
   65  		select distinct m.perms
   66  		from sys_menu m
   67  			 left join sys_role_menu rm on m.menu_id = rm.menu_id
   68  			 left join sys_user_role ur on rm.role_id = ur.role_id
   69  			 left join sys_role r on r.role_id = ur.role_id
   70  		where m.visible = '0' and r.status = '0' and ur.user_id = #{userId}
   71  	</select>
   72
   73  	<select id="selectPermsByRoleId" parameterType="Long" resultType="String">
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for /system/role/add, /system/role/edit, system:role:add/edit before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/RuoYi/issue1.html
