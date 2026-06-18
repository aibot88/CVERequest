---
title: "JEEWMS issue2: `updateAuthority` 可改写角色功能权限"
description: "JEEWMS has a missing authorization vulnerability: `updateAuthority` 可改写角色功能权限. 可给角色授予或移除菜单/功能权限，影响用户后续可访问功能和授权状态。"
tags:
  - JEEWMS
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JEEWMS has a missing authorization vulnerability: `updateAuthority` 可改写角色功能权限. 可给角色授予或移除菜单/功能权限，影响用户后续可访问功能和授权状态。

- Attack precondition: 攻击者能访问 `roleController.do?updateAuthority`。源码层面未证明该入口仅系统管理员可访问。
- Security impact: 可给角色授予或移除菜单/功能权限，影响用户后续可访问功能和授权状态。

### 1.2 Exploit path

提交任意 `roleId` 和 `rolefunctions`，服务端删除该角色旧功能绑定并新增请求中的功能绑定。

### 1.3 Key code evidence

1. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L580

```text
  577  	 * @param request
  578  	 * @return
  579  	 */
  580  	@RequestMapping(params = "updateAuthority")
  581  	@ResponseBody
  582  	public AjaxJson updateAuthority(HttpServletRequest request) {
  583  		AjaxJson j = new AjaxJson();
```

2. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L585

```text
  582  	@ResponseBody
  583  	public AjaxJson updateAuthority(HttpServletRequest request) {
  584  		AjaxJson j = new AjaxJson();
  585  		try {
  586  			String roleId = request.getParameter("roleId");
  587  			String rolefunction = request.getParameter("rolefunctions");
  588  			String scopeMessage = validateRoleAuthorityScope(roleId, rolefunction);
  589  			if (scopeMessage != null) {
  590  				j.setSuccess(false);
```

3. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L595

```text
  592  				return j;
  593  			}
  594  			TSRole role = this.systemService.get(TSRole.class, roleId);
  595  			List<TSRoleFunction> roleFunctionList = systemService
  596  					.findByProperty(TSRoleFunction.class, "TSRole.id",
  597  							role.getId());
  598  			Map<String, TSRoleFunction> map = new HashMap<String, TSRoleFunction>(1024);
  599  			for (TSRoleFunction functionOfRole : roleFunctionList) {
  600  				map.put(functionOfRole.getTSFunction().getId(), functionOfRole);
  601  			}
  602  			String[] roleFunctions = rolefunction.split(",");
  603  			Set<String> set = new HashSet<String>();
```

4. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L627

```text
  624  		}
  625  		if (!helper.canManageRole(currentUser, roleId)) {
  626  			return "没有权限操作该角色！";
  627  		}
  628  		for (String functionId : helper.parseIds(functionIds)) {
  629  			if (!helper.currentUserHasFunction(currentUser, functionId)) {
  630  				return "没有权限授予该功能！";
  631  			}
  632  		}
  633  		return null;
  634  	}
```

5. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L639

```text
  636  	/**
  637  	 * 权限比较
  638  	 * 
  639  	 * @param set
  640  	 *            最新的权限列表
  641  	 * @param role
  642  	 *            当前角色
  643  	 * @param map
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

将该接口强制限制为系统管理员或明确的角色管理权限；校验当前用户可管理目标角色，且只能授予自己权限范围内的功能。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JEEWMS/issue2.html
