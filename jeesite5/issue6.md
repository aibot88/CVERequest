---
title: "jeesite5 issue6: role/treeData?isAll=true"
description: "jeesite5 has a missing authorization vulnerability in GET/POST ${adminPath}/sys/role/treeData?isAll=true, role/treeData, id/code/name. An authenticated attacker can perform authorization-sensitive operations through GET/POST ${adminPath}/sys/role/treeData?isAll=true, role/treeData, id/code/name without the required permission."
tags:
  - jeesite5
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

jeesite5 has a missing authorization vulnerability in GET/POST ${adminPath}/sys/role/treeData?isAll=true, role/treeData, id/code/name. An authenticated attacker can perform authorization-sensitive operations through GET/POST ${adminPath}/sys/role/treeData?isAll=true, role/treeData, id/code/name without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `GET/POST ${adminPath}/sys/role/treeData?isAll=true, role/treeData, id/code/name`
- Affected authorization property: `strictMode=false, Role.roleCode, id, Role.viewCode, Role.roleName, isAll=true`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through GET/POST ${adminPath}/sys/role/treeData?isAll=true, role/treeData, id/code/name without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to GET/POST ${adminPath}/sys/role/treeData?isAll=true, role/treeData, id/code/name with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `modules/core/src/main/java/com/jeesite/modules/sys/web/RoleController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/RoleController.java#L209

```text
  206  		}
  207  	}
  208
  209  	/**
  210  	 * [non-English text removed]
  211  	 */
  212  	@RequiresPermissions("sys:role:view")
  213  	@RequestMapping(value = "menuTreeData")
  214  	@ResponseBody
  215  	public Map<String, Object> menuTreeData(Role role) {
  216  		Map<String, Object> model = MapUtils.newHashMap();
  217  		List<String> sysCodes = ListUtils.newArrayList();
  218  		for (DictData sysCode : DictUtils.getDictList("sys_menu_sys_code")) {
  219  			sysCodes.add(sysCode.getDictValue());
  220  		}
  221  		List<Menu> menuList = roleService.findManageMenuList(role);
  222  		Map<String, List<Map<String, String>>> map = MapUtils.newLinkedHashMap();
  223  		for (Menu menu : menuList){
  224  			// [non-English text removed]
  225  			if (!sysCodes.contains(menu.getSysCode())) {
  226  				continue;
  227  			}
  228  			List<Map<String, String>> list = map.computeIfAbsent(menu.getSysCode(), k -> ListUtils.newArrayList());
  229  			Map<String, String> m = MapUtils.newHashMap();
  230  			m.put("id", menu.getMenuCode());
  231  			m.put("pId", menu.getParentCode());
  232  			m.put("name", menu.getMenuName() + "<font color=#888> &nbsp; &nbsp; "
  233  					+ StringUtils.abbr(ObjectUtils.toString(menu.getPermission()) + " &nbsp; "
  234  					+ ObjectUtils.toString(menu.getMenuHref()), 50) + "</font>");
  235  			m.put("title", menu.getMenuName() + "&nbsp;"
```

2. `modules/core/src/main/java/com/jeesite/modules/sys/web/RoleController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/RoleController.java#L64

```text
   61  	@RequiresPermissions("sys:role:view")
   62  	@RequestMapping(value = "list")
   63  	public String list(Role role, Model model) {
   64  		model.addAttribute("role", role);
   65  		model.addAttribute("ctrlPermi", Global.getConfig("user.adminCtrlPermi", "2"));
   66  		return "modules/sys/roleList";
   67  	}
   68
   69  	@RequiresPermissions("sys:role:view")
   70  	@RequestMapping(value = "listData")
   71  	@ResponseBody
   72  	public Page<Role> listData(Role role, String ctrlPermi, HttpServletRequest request, HttpServletResponse response) {
   73  		// [non-English text removed],[non-English text removed]
   74  		if (!role.currentUser().isSuperAdmin()){
   75  			roleService.addDataScopeFilter(role, ctrlPermi);
   76  		}
   77  		role.setPage(new Page<>(request, response));
```

3. `modules/core/src/main/resources/db/create/mysql/core.sql`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/resources/db/create/mysql/core.sql#L735

```text
  732
  733  -- [non-English text removed]
  734  CREATE TABLE ${_prefix}sys_role
  735  (
  736  	role_code varchar(64) NOT NULL COMMENT '[non-English text removed]',
  737  	role_name varchar(100) NOT NULL COMMENT '[non-English text removed]',
  738  	view_code varchar(100) COMMENT '[non-English text removed]',
  739  	role_type varchar(100) COMMENT '[non-English text removed]([non-English text removed],[non-English text removed],[non-English text removed],[non-English text removed])',
  740  	role_sort decimal(10) COMMENT '[non-English text removed]([non-English text removed])',
  741  	is_sys char(1) COMMENT '[non-English text removed](1[non-English text removed] 0[non-English text removed])',
  742  	is_show char(1) DEFAULT '1' COMMENT '[non-English text removed]',
  743  	user_type varchar(16) COMMENT '[non-English text removed](employee[non-English text removed] member[non-English text removed])',
  744  	desktop_url varchar(255) COMMENT '[non-English text removed]([non-English text removed])',
  745  	data_scope char(1) COMMENT '[non-English text removed](0[non-English text removed] 1[non-English text removed] 2[non-English text removed])',
  746  	biz_scope varchar(255) COMMENT '[non-English text removed]([non-English text removed],[non-English text removed])',
  747  	sys_codes varchar(500) COMMENT '[non-English text removed]([non-English text removed])',
  748  	status char(1) DEFAULT '0' NOT NULL COMMENT '[non-English text removed](0[non-English text removed] 1[non-English text removed] 2[non-English text removed])',
  749  	create_by varchar(64) NOT NULL COMMENT '[non-English text removed]',
  750  	create_date datetime NOT NULL COMMENT '[non-English text removed]',
  751  	update_by varchar(64) NOT NULL COMMENT '[non-English text removed]',
  752  	update_date datetime NOT NULL COMMENT '[non-English text removed]',
  753  	remarks varchar(500) COMMENT '[non-English text removed]',
  754  	corp_code varchar(64) DEFAULT '0' NOT NULL COMMENT '[non-English text removed]',
  755  	corp_name varchar(100) DEFAULT 'JeeSite' NOT NULL COMMENT '[non-English text removed]',
  756  	extend_s1 varchar(500) COMMENT '[non-English text removed] String 1',
  757  	extend_s2 varchar(500) COMMENT '[non-English text removed] String 2',
  758  	extend_s3 varchar(500) COMMENT '[non-English text removed] String 3',
  759  	extend_s4 varchar(500) COMMENT '[non-English text removed] String 4',
  760  	extend_s5 varchar(500) COMMENT '[non-English text removed] String 5',
  761  	extend_s6 varchar(500) COMMENT '[non-English text removed] String 6',
  762  	extend_s7 varchar(500) COMMENT '[non-English text removed] String 7',
  763  	extend_s8 varchar(500) COMMENT '[non-English text removed] String 8',
  764  	extend_i1 decimal(19) COMMENT '[non-English text removed] Integer 1',
  765  	extend_i2 decimal(19) COMMENT '[non-English text removed] Integer 2',
  766  	extend_i3 decimal(19) COMMENT '[non-English text removed] Integer 3',
  767  	extend_i4 decimal(19) COMMENT '[non-English text removed] Integer 4',
  768  	extend_f1 decimal(19,4) COMMENT '[non-English text removed] Float 1',
  769  	extend_f2 decimal(19,4) COMMENT '[non-English text removed] Float 2',
  770  	extend_f3 decimal(19,4) COMMENT '[non-English text removed] Float 3',
  771  	extend_f4 decimal(19,4) COMMENT '[non-English text removed] Float 4',
  772  	extend_d1 datetime COMMENT '[non-English text removed] Date 1',
  773  	extend_d2 datetime COMMENT '[non-English text removed] Date 2',
  774  	extend_d3 datetime COMMENT '[non-English text removed] Date 3',
  775  	extend_d4 datetime COMMENT '[non-English text removed] Date 4',
  776  	extend_json varchar(1000) COMMENT '[non-English text removed] JSON',
  777  	PRIMARY KEY (role_code)
  778  ) COMMENT = '[non-English text removed]';
  779
  780
  781  -- [non-English text removed]
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for GET/POST ${adminPath}/sys/role/treeData?isAll=true, role/treeData, id/code/name before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/jeesite5/issue6.html
