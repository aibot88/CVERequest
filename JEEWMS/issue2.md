---
title: "JEEWMS issue2: `updateAuthority`"
description: "JEEWMS has a missing authorization vulnerability. An authenticated attacker can perform authorization-sensitive operations without the required permission."
tags:
  - JEEWMS
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JEEWMS has a missing authorization vulnerability. An authenticated attacker can perform authorization-sensitive operations without the required permission.

- Attack precondition: Any authenticated user
- Affected authorization property: `roleController.do?updateAuthority, roleId, rolefunctions, TSRoleFunction, @RequestMapping(params = "updateAuthority"), updateCompare`
- Security impact: An authenticated attacker can perform authorization-sensitive operations without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to the affected endpoint with target identifiers or authorization-sensitive fields that should be rejected.

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

2. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L585

```text
  582  	public AjaxJson updateAuthority(HttpServletRequest request) {
  583  		AjaxJson j = new AjaxJson();
  584  		try {
  585  			String roleId = request.getParameter("roleId");
  586  			String rolefunction = request.getParameter("rolefunctions");
  587  			TSRole role = this.systemService.get(TSRole.class, roleId);
  588  			List<TSRoleFunction> roleFunctionList = systemService
  589  					.findByProperty(TSRoleFunction.class, "TSRole.id",
  590  							role.getId());
```

3. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L595

```text
  592  			for (TSRoleFunction functionOfRole : roleFunctionList) {
  593  				map.put(functionOfRole.getTSFunction().getId(), functionOfRole);
  594  			}
  595  			String[] roleFunctions = rolefunction.split(",");
  596  			Set<String> set = new HashSet<String>();
  597  			for (String s : roleFunctions) {
  598  				set.add(s);
  599  			}
  600  			updateCompare(set, role, map);
  601  			j.setMsg("[non-English text removed]");
  602  		} catch (Exception e) {
  603  			logger.error(ExceptionUtil.getExceptionMessage(e));
```

4. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L627

```text
  624  			if (map.containsKey(s)) {
  625  				map.remove(s);
  626  			} else {
  627  				TSRoleFunction rf = new TSRoleFunction();
  628  				TSFunction f = this.systemService.get(TSFunction.class, s);
  629  				rf.setTSFunction(f);
  630  				rf.setTSRole(role);
  631  				entitys.add(rf);
  632  			}
  633  		}
  634  		Collection<TSRoleFunction> collection = map.values();
```

5. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L639

```text
  636  		for (; it.hasNext();) {
  637  			deleteEntitys.add(it.next());
  638  		}
  639  		systemService.batchSave(entitys);
  640  		systemService.deleteAllEntitie(deleteEntitys);
  641
  642  	}
  643
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for the vulnerable operation before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JEEWMS/issue2.html
