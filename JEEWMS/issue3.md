---
title: "JEEWMS issue3: `updateDataRule` 可改写角色数据规则"
description: "JEEWMS has a missing authorization vulnerability: `updateDataRule` 可改写角色数据规则. 可扩大、清空或替换角色在某功能下的数据权限规则，影响后续数据过滤范围。"
tags:
  - JEEWMS
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JEEWMS has a missing authorization vulnerability: `updateDataRule` 可改写角色数据规则. 可扩大、清空或替换角色在某功能下的数据权限规则，影响后续数据过滤范围。

- Attack precondition: 攻击者能访问 `roleController.do?updateDataRule`。源码层面未证明该入口仅系统管理员可访问。
- Security impact: 可扩大、清空或替换角色在某功能下的数据权限规则，影响后续数据过滤范围。

### 1.2 Exploit path

提交任意 `roleId`、`functionId` 和 `dataRulecodes`，修改对应 `TSRoleFunction.dataRule`。

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

2. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L879

```text
  876  	 * @param roleId
  877  	 * @return
  878  	 */
  879  	@RequestMapping(params = "dataRuleListForFunction")
  880  	public ModelAndView dataRuleListForFunction(HttpServletRequest request,
  881  			String functionId, String roleId) {
  882  		CriteriaQuery cq = new CriteriaQuery(TSDataRule.class);
  883  		cq.eq("TSFunction.id", functionId);
  884  		cq.add();
  885  		List<TSDataRule> dataRuleList = this.systemService
  886  				.getListByCriteriaQuery(cq, false);
  887  		Set<String> dataRulecodes = systemService
  888  				.getOperationCodesByRoleIdAndruleDataId(roleId, functionId);
```

3. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L890

```text
  887  		Set<String> dataRulecodes = systemService
  888  				.getOperationCodesByRoleIdAndruleDataId(roleId, functionId);
  889  		request.setAttribute("dataRuleList", dataRuleList);
  890  		request.setAttribute("dataRulecodes", dataRulecodes);
  891  		request.setAttribute("functionId", functionId);
  892  		return new ModelAndView("system/role/dataRuleListForFunction");
  893  	}
  894  	
  895  	
  896  	/**
  897  	 * 更新按钮权限
  898  	 * 
```

4. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L897

```text
  894  	
  895  	
  896  	/**
  897  	 * 更新按钮权限
  898  	 * 
  899  	 * @param request
  900  	 * @return
  901  	 */
  902  	@RequestMapping(params = "updateDataRule")
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

仅允许系统管理员或被授权的数据权限管理员修改；校验目标角色、目标功能和规则表达式均在当前用户可管理范围内；禁止非管理员清空或扩大规则。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JEEWMS/issue3.html
