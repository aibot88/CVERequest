---
title: "RuoYi issue5: Department Hierarchy Rebinding"
description: "RuoYi has a missing authorization vulnerability in /system/dept/add, /system/dept/edit, /add/{parentId}, /add. An authenticated attacker can perform authorization-sensitive operations through /system/dept/add, /system/dept/edit, /add/{parentId}, /add without the required permission."
tags:
  - RuoYi
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

RuoYi has a missing authorization vulnerability in /system/dept/add, /system/dept/edit, /add/{parentId}, /add. An authenticated attacker can perform authorization-sensitive operations through /system/dept/add, /system/dept/edit, /add/{parentId}, /add without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `/system/dept/add, /system/dept/edit, /add/{parentId}, /add`
- Affected authorization property: ``sys_dept.parent_id`, `sys_dept.ancestors``
- Security impact: An authenticated attacker can perform authorization-sensitive operations through /system/dept/add, /system/dept/edit, /add/{parentId}, /add without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to /system/dept/add, /system/dept/edit, /add/{parentId}, /add with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysDeptController.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysDeptController.java#L77

```text
   74      @PostMapping("/add")
   75      @ResponseBody
   76      public AjaxResult addSave(@Validated SysDept dept)
   77      {
   78          if (!deptService.checkDeptNameUnique(dept))
   79          {
   80              return error("[non-English text removed]'" + dept.getDeptName() + "'[non-English text removed],[non-English text removed]");
   81          }
   82          dept.setCreateBy(getLoginName());
   83          return toAjax(deptService.insertDept(dept));
   84      }
   85
   86      /**
   87       * [non-English text removed]
```

2. `ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysDeptServiceImpl.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysDeptServiceImpl.java#L193

```text
  190       * @return [non-English text removed]
  191       */
  192      @Override
  193      public int insertDept(SysDept dept)
  194      {
  195          SysDept info = deptMapper.selectDeptById(dept.getParentId());
  196          // [non-English text removed]"[non-English text removed]"[non-English text removed],[non-English text removed]
  197          if (!UserConstants.DEPT_NORMAL.equals(info.getStatus()))
  198          {
  199              throw new ServiceException("[non-English text removed],[non-English text removed]");
  200          }
  201          dept.setAncestors(info.getAncestors() + "," + dept.getParentId());
  202          return deptMapper.insertDept(dept);
  203      }
  204
  205      /**
  206       * [non-English text removed]
  207       *
  208       * @param dept [non-English text removed]
  209       * @return [non-English text removed]
  210       */
  211      @Override
  212      @Transactional
  213      public int updateDept(SysDept dept)
  214      {
  215          SysDept newParentDept = deptMapper.selectDeptById(dept.getParentId());
  216          SysDept oldDept = selectDeptById(dept.getDeptId());
  217          if (StringUtils.isNotNull(newParentDept) && StringUtils.isNotNull(oldDept))
  218          {
  219              String newAncestors = newParentDept.getAncestors() + "," + newParentDept.getDeptId();
  220              String oldAncestors = oldDept.getAncestors();
  221              dept.setAncestors(newAncestors);
  222              updateDeptChildren(dept.getDeptId(), newAncestors, oldAncestors);
  223          }
  224          int result = deptMapper.updateDept(dept);
  225          if (UserConstants.DEPT_NORMAL.equals(dept.getStatus()) && StringUtils.isNotEmpty(dept.getAncestors())
  226                  && !StringUtils.equals("0", dept.getAncestors()))
  227          {
```

3. `ruoyi-system/src/main/resources/mapper/system/SysDeptMapper.xml`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/resources/mapper/system/SysDeptMapper.xml#L89

```text
   86  		select count(*) from sys_dept where status = 0 and del_flag = '0' and find_in_set(#{deptId}, ancestors)
   87  	</select>
   88
   89  	<insert id="insertDept" parameterType="SysDept">
   90   		insert into sys_dept(
   91   			<if test="deptId != null and deptId != 0">dept_id,</if>
   92   			<if test="parentId != null and parentId != 0">parent_id,</if>
   93   			<if test="deptName != null and deptName != ''">dept_name,</if>
   94   			<if test="ancestors != null and ancestors != ''">ancestors,</if>
   95   			<if test="orderNum != null">order_num,</if>
   96   			<if test="leader != null and leader != ''">leader,</if>
   97   			<if test="phone != null and phone != ''">phone,</if>
   98   			<if test="email != null and email != ''">email,</if>
   99   			<if test="status != null">status,</if>
  100   			<if test="createBy != null and createBy != ''">create_by,</if>
  101   			create_time
  102   		)values(
  103   			<if test="deptId != null and deptId != 0">#{deptId},</if>
  104   			<if test="parentId != null and parentId != 0">#{parentId},</if>
  105   			<if test="deptName != null and deptName != ''">#{deptName},</if>
  106   			<if test="ancestors != null and ancestors != ''">#{ancestors},</if>
  107   			<if test="orderNum != null">#{orderNum},</if>
  108   			<if test="leader != null and leader != ''">#{leader},</if>
  109   			<if test="phone != null and phone != ''">#{phone},</if>
  110   			<if test="email != null and email != ''">#{email},</if>
  111   			<if test="status != null">#{status},</if>
  112   			<if test="createBy != null and createBy != ''">#{createBy},</if>
  113   			sysdate()
  114   		)
  115  	</insert>
  116
  117  	<update id="updateDept" parameterType="SysDept">
  118   		update sys_dept
  119   		<set>
  120   			<if test="parentId != null and parentId != 0">parent_id = #{parentId},</if>
  121   			<if test="deptName != null and deptName != ''">dept_name = #{deptName},</if>
  122   			<if test="ancestors != null and ancestors != ''">ancestors = #{ancestors},</if>
  123   			<if test="orderNum != null">order_num = #{orderNum},</if>
  124   			<if test="leader != null">leader = #{leader},</if>
  125   			<if test="phone != null">phone = #{phone},</if>
  126   			<if test="email != null">email = #{email},</if>
  127   			<if test="status != null and status != ''">status = #{status},</if>
  128   			<if test="updateBy != null and updateBy != ''">update_by = #{updateBy},</if>
  129   			update_time = sysdate()
  130   		</set>
  131   		where dept_id = #{deptId}
  132  	</update>
  133
  134  	<update id="updateDeptChildren" parameterType="java.util.List">
```

4. `ruoyi-framework/src/main/java/com/ruoyi/framework/aspectj/DataScopeAspect.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-framework/src/main/java/com/ruoyi/framework/aspectj/DataScopeAspect.java#L100

```text
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

Enforce server-side authorization for /system/dept/add, /system/dept/edit, /add/{parentId}, /add before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/RuoYi/issue5.html
