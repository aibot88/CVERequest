---
title: "RuoYi issue2: Role Data Scope Escalation"
description: "RuoYi has a missing authorization vulnerability in /system/role/authDataScope. An authenticated attacker can perform authorization-sensitive operations through /system/role/authDataScope without the required permission."
tags:
  - RuoYi
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

RuoYi has a missing authorization vulnerability in /system/role/authDataScope. An authenticated attacker can perform authorization-sensitive operations through /system/role/authDataScope without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `/system/role/authDataScope`
- Affected authorization property: ``sys_role.data_scope`, `sys_role_dept.role_id`, `sys_role_dept.dept_id`, `SysRole.deptIds``
- Security impact: An authenticated attacker can perform authorization-sensitive operations through /system/role/authDataScope without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to /system/role/authDataScope with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java#L165

```text
  162      @Log(title = "[non-English text removed]", businessType = BusinessType.UPDATE)
  163      @PostMapping("/authDataScope")
  164      @ResponseBody
  165      public AjaxResult authDataScopeSave(SysRole role)
  166      {
  167          roleService.checkRoleAllowed(role);
  168          roleService.checkRoleDataScope(role.getRoleId());
  169          role.setUpdateBy(getLoginName());
  170          if (roleService.authDataScope(role) > 0)
  171          {
  172              setSysUser(userService.selectUserById(getUserId()));
  173              return success();
  174          }
  175          return error();
  176      }
  177
```

2. `ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysRoleServiceImpl.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysRoleServiceImpl.java#L215

```text
  212       * @param role [non-English text removed]
  213       * @return [non-English text removed]
  214       */
  215      @Override
  216      @Transactional
  217      public int authDataScope(SysRole role)
  218      {
  219          // [non-English text removed]
  220          roleMapper.updateRole(role);
  221          // [non-English text removed]
  222          roleDeptMapper.deleteRoleDeptByRoleId(role.getRoleId());
  223          // [non-English text removed]([non-English text removed])
  224          return insertRoleDept(role);
  225      }
```

3. `ruoyi-system/src/main/resources/mapper/system/SysRoleMapper.xml`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/resources/mapper/system/SysRoleMapper.xml#L95

```text
   92          </foreach>
   93   	</delete>
   94
   95   	<update id="updateRole" parameterType="SysRole">
   96   		update sys_role
   97   		<set>
   98   			<if test="roleName != null and roleName != ''">role_name = #{roleName},</if>
   99   			<if test="roleKey != null and roleKey != ''">role_key = #{roleKey},</if>
  100   			<if test="roleSort != null and roleSort != ''">role_sort = #{roleSort},</if>
  101   			<if test="dataScope != null and dataScope != ''">data_scope = #{dataScope},</if>
  102   			<if test="status != null and status != ''">status = #{status},</if>
  103   			<if test="remark != null">remark = #{remark},</if>
  104   			<if test="updateBy != null and updateBy != ''">update_by = #{updateBy},</if>
  105   			update_time = sysdate()
  106   		</set>
  107   		where role_id = #{roleId}
  108  	</update>
  109
  110   	<insert id="insertRole" parameterType="SysRole" useGeneratedKeys="true" keyProperty="roleId">
```

4. `ruoyi-framework/src/main/java/com/ruoyi/framework/aspectj/DataScopeAspect.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-framework/src/main/java/com/ruoyi/framework/aspectj/DataScopeAspect.java#L79

```text
   76              }
   77          }
   78      }
   79
   80      /**
   81       * [non-English text removed]
   82       *
   83       * @param joinPoint [non-English text removed]
   84       * @param user [non-English text removed]
   85       * @param deptAlias [non-English text removed]
   86       * @param userAlias [non-English text removed]
   87       * @param permission [non-English text removed]
   88       */
   89      public static void dataScopeFilter(JoinPoint joinPoint, SysUser user, String deptAlias, String userAlias, String permission)
   90      {
   91          StringBuilder sqlString = new StringBuilder();
   92          List<String> conditions = new ArrayList<String>();
   93          List<String> scopeCustomIds = new ArrayList<String>();
   94          user.getRoles().forEach(role -> {
   95              if (DATA_SCOPE_CUSTOM.equals(role.getDataScope()) && StringUtils.equals(role.getStatus(), UserConstants.ROLE_NORMAL) && (StringUtils.isEmpty(permission) || StringUtils.containsAny(role.getPermissions(), Convert.toStrArray(permission))))
   96              {
   97                  scopeCustomIds.add(Convert.toStr(role.getRoleId()));
   98              }
   99          });
  100
  101          for (SysRole role : user.getRoles())
  102          {
  103              String dataScope = role.getDataScope();
  104              if (conditions.contains(dataScope) || StringUtils.equals(role.getStatus(), UserConstants.ROLE_DISABLE))
  105              {
  106                  continue;
  107              }
  108              if (StringUtils.isNotEmpty(permission) && !StringUtils.containsAny(role.getPermissions(), Convert.toStrArray(permission)))
  109              {
  110                  continue;
  111              }
  112              if (DATA_SCOPE_ALL.equals(dataScope))
  113              {
  114                  sqlString = new StringBuilder();
  115                  conditions.add(dataScope);
```

5. `deptService.c`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/deptService.c

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for /system/role/authDataScope before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/RuoYi/issue2.html
