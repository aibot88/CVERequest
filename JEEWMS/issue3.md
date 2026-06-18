---
title: "JEEWMS issue3: `updateDataRule`"
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
- Affected authorization property: `roleController.do?updateDataRule, roleId, functionId, dataRulecodes, TSRoleFunction.dataRule, dataRule`
- Security impact: An authenticated attacker can perform authorization-sensitive operations without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to the affected endpoint with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L875

```text
  872  	 * @param request
  873  	 * @return
  874  	 */
  875  	@RequestMapping(params = "updateDataRule")
  876  	@ResponseBody
  877  	public AjaxJson updateDataRule(HttpServletRequest request) {
  878  		AjaxJson j = new AjaxJson();
```

2. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L879

```text
  876  	@ResponseBody
  877  	public AjaxJson updateDataRule(HttpServletRequest request) {
  878  		AjaxJson j = new AjaxJson();
  879  		String roleId = request.getParameter("roleId");
  880  		String functionId = request.getParameter("functionId");
  881
  882  		String dataRulecodes = null;
  883  		try {
  884  			dataRulecodes = URLDecoder.decode(
  885  					request.getParameter("dataRulecodes"), "utf-8");
  886  		} catch (UnsupportedEncodingException e) {
  887  			e.printStackTrace();
  888  		}
```

3. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L890

```text
  887  			e.printStackTrace();
  888  		}
  889
  890  		CriteriaQuery cq1 = new CriteriaQuery(TSRoleFunction.class);
  891  		cq1.eq("TSRole.id", roleId);
  892  		cq1.eq("TSFunction.id", functionId);
  893  		cq1.add();
  894  		List<TSRoleFunction> rFunctions = systemService.getListByCriteriaQuery(
  895  				cq1, false);
  896  		if (null != rFunctions && rFunctions.size() > 0) {
  897  			TSRoleFunction tsRoleFunction = rFunctions.get(0);
  898  			tsRoleFunction.setDataRule(dataRulecodes);
```

4. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L897

```text
  894  		List<TSRoleFunction> rFunctions = systemService.getListByCriteriaQuery(
  895  				cq1, false);
  896  		if (null != rFunctions && rFunctions.size() > 0) {
  897  			TSRoleFunction tsRoleFunction = rFunctions.get(0);
  898  			tsRoleFunction.setDataRule(dataRulecodes);
  899  			systemService.saveOrUpdate(tsRoleFunction);
  900  		}
  901  		j.setMsg("[non-English text removed]");
  902  		return j;
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

Published reference: https://aibot88.github.io/CVERequest/JEEWMS/issue3.html
