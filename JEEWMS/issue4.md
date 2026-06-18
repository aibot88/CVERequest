---
title: "JEEWMS issue4: `doAddUserToRole` 可批量添加用户到任意角色"
description: "JEEWMS has a missing authorization vulnerability: `doAddUserToRole` 可批量添加用户到任意角色. 可将自己或其他用户加入高权限角色，直接提升系统权限。"
tags:
  - JEEWMS
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JEEWMS has a missing authorization vulnerability: `doAddUserToRole` 可批量添加用户到任意角色. 可将自己或其他用户加入高权限角色，直接提升系统权限。

- Attack precondition: 攻击者能访问 `roleController.do?doAddUserToRole`。不要求已经拥有目标角色管理权。
- Security impact: 可将自己或其他用户加入高权限角色，直接提升系统权限。

### 1.2 Exploit path

提交任意 `roleId` 和逗号分隔的 `userIds`，服务端批量创建 `TSRoleUser`。

### 1.3 Key code evidence

1. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L947

```text
  944       * @param req request
  945       * @return 处理结果信息
  946       */
  947      @RequestMapping(params = "doAddUserToRole")
  948      @ResponseBody
  949      public AjaxJson doAddUserToOrg(HttpServletRequest req) {
  950      	String message = null;
```

2. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L952

```text
  949  		}
  950  		if (!helper.currentUserHasFunction(currentUser, functionId)) {
  951  			return "没有权限授予该功能的数据规则！";
  952  		}
  953  		if (!helper.canGrantDataRules(currentUser, functionId, helper.parseIds(dataRuleIds))) {
  954  			return "没有权限授予该数据规则！";
  955  		}
  956  		return null;
```

3. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L966

```text
  963       * @param req request
  964       * @return 处理结果信息
  965       */
  966      @RequestMapping(params = "goAddUserToRole")
  967      public ModelAndView goAddUserToOrg(HttpServletRequest req) {
  968          return new ModelAndView("system/role/noCurRoleUserList");
  969      }
  970      
  971      /**
  972       * 获取 除当前 角色之外的用户信息列表
  973       * @param request request
  974       * @return 处理结果信息
  975       */
  976      @RequestMapping(params = "addUserToRoleList")
  977      public void addUserToOrgList(TSUser user, HttpServletRequest request, HttpServletResponse response, DataGrid dataGrid) {
  978          String roleId = request.getParameter("roleId");
  979  
  980          CriteriaQuery cq = new CriteriaQuery(TSUser.class, dataGrid);
  981          org.jeecgframework.core.extend.hqlsearch.HqlGenerateUtil.installHql(cq, user);
  982  
  983          // 获取 当前组织机构的用户信息
  984          CriteriaQuery subCq = new CriteriaQuery(TSRoleUser.class);
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

校验调用者对目标角色和目标用户的管理权；禁止授予高于自身的角色；增加唯一约束防止重复绑定。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JEEWMS/issue4.html
