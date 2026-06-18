---
title: "RuoYi issue6: Menu Permission Property Overwrite"
description: "RuoYi has a missing authorization vulnerability: Menu Permission Property Overwrite. 破坏菜单权限资源边界；`perms` 会被 Shiro 作为权限字符串加载，可能使角色权限语义被篡改。"
tags:
  - RuoYi
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

RuoYi has a missing authorization vulnerability: Menu Permission Property Overwrite. 破坏菜单权限资源边界；`perms` 会被 Shiro 作为权限字符串加载，可能使角色权限语义被篡改。

- Attack precondition: 非超级管理员拥有 `system:menu:add`、`system:menu:edit` 或相关菜单管理权限。
- Affected authorization property: ``sys_menu.perms`, `sys_menu.parent_id`, `sys_menu.visible`, `sys_menu.menu_type`。核心 MRBPC 点为 `sys_menu.perms`。`
- Security impact: 破坏菜单权限资源边界；`perms` 会被 Shiro 作为权限字符串加载，可能使角色权限语义被篡改。

### 1.2 Exploit path

POST `/system/menu/add` 或 `/system/menu/edit`，提交不可管理的 `menuId/parentId`，或将菜单 `perms` 改成更高权限字符串。

### 1.3 Key code evidence

1. `ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysMenuController.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysMenuController.java#L104

```text
  101       * 新增保存菜单
  102       */
  103      @Log(title = "菜单管理", businessType = BusinessType.INSERT)
  104      @RequiresPermissions("system:menu:add")
  105      @PostMapping("/add")
  106      @ResponseBody
  107      public AjaxResult addSave(@Validated SysMenu menu)
  108      {
  109          if (!menuService.checkMenuNameUnique(menu))
  110          {
  111              return error("新增菜单'" + menu.getMenuName() + "'失败，菜单名称已存在");
  112          }
  113          menu.setCreateBy(getLoginName());
  114          AuthorizationUtils.clearAllCachedAuthorizationInfo();
  115          return toAjax(menuService.insertMenu(menu));
  116      }
  117  
  118      /**
  119       * 修改菜单
  120       */
  121      @RequiresPermissions("system:menu:edit")
  122      @GetMapping("/edit/{menuId}")
  123      public String edit(@PathVariable("menuId") Long menuId, ModelMap mmap)
  124      {
  125          mmap.put("menu", menuService.selectMenuById(menuId));
  126          return prefix + "/edit";
  127      }
  128  
  129      /**
  130       * 修改保存菜单
  131       */
  132      @Log(title = "菜单管理", businessType = BusinessType.UPDATE)
  133      @RequiresPermissions("system:menu:edit")
  134      @PostMapping("/edit")
  135      @ResponseBody
  136      public AjaxResult editSave(@Validated SysMenu menu)
  137      {
  138          if (!menuService.checkMenuNameUnique(menu))
  139          {
  140              return error("修改菜单'" + menu.getMenuName() + "'失败，菜单名称已存在");
  141          }
  142          menu.setUpdateBy(getLoginName());
  143          AuthorizationUtils.clearAllCachedAuthorizationInfo();
  144          return toAjax(menuService.updateMenu(menu));
  145      }
  146  
  147      /**
  148       * 保存菜单排序
  149       */
  150      @PostMapping("/updateSort")
  151      @ResponseBody
  152      public AjaxResult updateSort(@RequestParam String[] menuIds, @RequestParam String[] orderNums)
  153      {
  154          menuService.updateMenuSort(menuIds, orderNums);
  155          return success();
  156      }
  157  
  158      /**
  159       * 选择菜单图标
```

2. `ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysMenuServiceImpl.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysMenuServiceImpl.java#L72

```text
   69       * @return 所有菜单信息
   70       */
   71      @Override
   72      public List<SysMenu> selectMenuList(SysMenu menu, Long userId)
   73      {
   74          List<SysMenu> menuList = null;
   75          if (ShiroUtils.isAdmin(userId))
   76          {
   77              menuList = menuMapper.selectMenuList(menu);
   78          }
   79          else
   80          {
   81              menu.getParams().put("userId", userId);
   82              menuList = menuMapper.selectMenuListByUserId(menu);
   83          }
   84          return menuList;
   85      }
   86  
   87      /**
   88       * 查询菜单集合
   89       * 
   90       * @return 所有菜单信息
   91       */
   92      @Override
   93      public List<SysMenu> selectMenuAll(Long userId)
   94      {
   95          List<SysMenu> menuList = null;
   96          if (ShiroUtils.isAdmin(userId))
   97          {
   98              menuList = menuMapper.selectMenuAll();
   99          }
  100          else
  101          {
  102              menuList = menuMapper.selectMenuAllByUserId(userId);
  103          }
  104          return menuList;
  105      }
  106  
  107      /**
```

3. `ruoyi-system/target/classes/mapper/system/SysMenuMapper.xml`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-system/target/classes/mapper/system/SysMenuMapper.xml#L137

```text
  134  		where menu_name=#{menuName} and parent_id = #{parentId} limit 1
  135  	</select>
  136  
  137  	<update id="updateMenu" parameterType="SysMenu">
  138  		update sys_menu
  139  		<set>
  140  			<if test="menuName != null and menuName != ''">menu_name = #{menuName},</if>
  141  			<if test="parentId != null and parentId != 0">parent_id = #{parentId},</if>
  142  			<if test="orderNum != null">order_num = #{orderNum},</if>
  143  			<if test="url != null">url = #{url},</if>
  144  			<if test="target != null and target != ''">target = #{target},</if>
  145  			<if test="menuType != null and menuType != ''">menu_type = #{menuType},</if>
  146  			<if test="visible != null">visible = #{visible},</if>
  147  			<if test="isRefresh != null">is_refresh = #{isRefresh},</if>
  148  			<if test="perms !=null">perms = #{perms},</if>
  149  			<if test="icon !=null and icon != ''">icon = #{icon},</if>
  150  			<if test="remark != null">remark = #{remark},</if>
  151  			<if test="updateBy != null and updateBy != ''">update_by = #{updateBy},</if>
  152  			update_time = sysdate()
  153  		</set>
  154  		where menu_id = #{menuId}
  155  	</update>
  156  
  157  	<insert id="insertMenu" parameterType="SysMenu">
  158  		insert into sys_menu(
  159  		<if test="menuId != null and menuId != 0">menu_id,</if>
  160  		<if test="parentId != null and parentId != 0">parent_id,</if>
  161  		<if test="menuName != null and menuName != ''">menu_name,</if>
  162  		<if test="orderNum != null">order_num,</if>
  163  		<if test="url != null and url != ''">url,</if>
  164  		<if test="target != null and target != ''">target,</if>
  165  		<if test="menuType != null and menuType != ''">menu_type,</if>
  166  		<if test="visible != null">visible,</if>
  167  		<if test="isRefresh != null">is_refresh,</if>
  168  		<if test="perms !=null and perms != ''">perms,</if>
  169  		<if test="icon != null and icon != ''">icon,</if>
  170  		<if test="remark != null and remark != ''">remark,</if>
  171  		<if test="createBy != null and createBy != ''">create_by,</if>
  172  		create_time
  173  		)values(
  174  		<if test="menuId != null and menuId != 0">#{menuId},</if>
  175  		<if test="parentId != null and parentId != 0">#{parentId},</if>
  176  		<if test="menuName != null and menuName != ''">#{menuName},</if>
  177  		<if test="orderNum != null">#{orderNum},</if>
  178  		<if test="url != null and url != ''">#{url},</if>
  179  		<if test="target != null and target != ''">#{target},</if>
  180  		<if test="menuType != null and menuType != ''">#{menuType},</if>
  181  		<if test="visible != null">#{visible},</if>
  182  		<if test="isRefresh != null">#{isRefresh},</if>
  183  		<if test="perms !=null and perms != ''">#{perms},</if>
  184  		<if test="icon != null and icon != ''">#{icon},</if>
  185  		<if test="remark != null and remark != ''">#{remark},</if>
  186  		<if test="createBy != null and createBy != ''">#{createBy},</if>
  187  		sysdate()
  188  		)
  189  	</insert>
  190  
  191  	<update id="updateMenuSort" parameterType="SysMenu">
  192  	    update sys_menu
  193  	    set order_num = #{orderNum}
  194  	    where menu_id = #{menuId}
  195  	</update>
  196  
  197  </mapper> 
```

4. `ruoyi-framework/src/main/java/com/ruoyi/framework/shiro/realm/UserRealm.java`

Evidence location: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-framework/src/main/java/com/ruoyi/framework/shiro/realm/UserRealm.java#L73

```text
   70          }
   71          else
   72          {
   73              roles = roleService.selectRoleKeys(user.getUserId());
   74              menus = menuService.selectPermsByUserId(user.getUserId());
   75              // 角色加入AuthorizationInfo认证对象
   76              info.setRoles(roles);
   77              // 权限加入AuthorizationInfo认证对象
   78              info.setStringPermissions(menus);
   79          }
   80          return info;
   81      }
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

菜单管理写接口仅允许超级管理员访问，或对 `menuId/parentId` 校验属于当前用户可管理菜单集合，并限制 `perms` 不能超出操作者权限集合。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/RuoYi/issue6.html
