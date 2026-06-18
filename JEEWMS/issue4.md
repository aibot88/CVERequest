---
title: "JEEWMS issue4: `doAddUserToRole`"
description: "JEEWMS has a missing authorization vulnerability in roleId/userIds. An authenticated attacker can perform authorization-sensitive operations through roleId/userIds without the required permission."
tags:
  - JEEWMS
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JEEWMS has a missing authorization vulnerability in roleId/userIds. An authenticated attacker can perform authorization-sensitive operations through roleId/userIds without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `roleId/userIds`
- Affected authorization property: `roleController.do?doAddUserToRole, roleId, userIds, TSRoleUser, @RequestMapping(params = "doAddUserToRole"), batchSave`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through roleId/userIds without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to roleId/userIds with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L947

```text
  944       * @param req request
  945       * @return [non-English text removed]
  946       */
  947      @RequestMapping(params = "doAddUserToRole")
  948      @ResponseBody
  949      public AjaxJson doAddUserToOrg(HttpServletRequest req) {
  950      	String message = null;
```

2. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L952

```text
  949      public AjaxJson doAddUserToOrg(HttpServletRequest req) {
  950      	String message = null;
  951          AjaxJson j = new AjaxJson();
  952          TSRole role = systemService.getEntity(TSRole.class, req.getParameter("roleId"));
  953          saveRoleUserList(req, role);
  954          message =  MutiLangUtil.paramAddSuccess("common.user");
  955  //      systemService.addLog(message, Globals.Log_Type_UPDATE, Globals.Log_Leavel_INFO);
  956          j.setMsg(message);
```

3. `src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/RoleController.java#L966

```text
  963       * @param depart depart
  964       */
  965      private void saveRoleUserList(HttpServletRequest request, TSRole role) {
  966          String userIds = oConvertUtils.getString(request.getParameter("userIds"));
  967
  968          List<TSRoleUser> roleUserList = new ArrayList<TSRoleUser>();
  969          List<String> userIdList = extractIdListByComma(userIds);
  970          for (String userId : userIdList) {
  971              TSUser user = new TSUser();
  972              user.setId(userId);
  973
  974              TSRoleUser roleUser = new TSRoleUser();
  975              roleUser.setTSUser(user);
  976              roleUser.setTSRole(role);
  977
  978              roleUserList.add(roleUser);
  979          }
  980          if (!roleUserList.isEmpty()) {
  981              systemService.batchSave(roleUserList);
  982          }
  983      }
  984
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for roleId/userIds before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JEEWMS/issue4.html
