---
title: "JEEWMS issue1: `saveUser`"
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
- Affected authorization property: `userController.do?saveUser, id, roleid, orgIds, TSRoleUser, TSUserOrg`
- Security impact: An authenticated attacker can perform authorization-sensitive operations without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to the affected endpoint with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `src/main/java/org/jeecgframework/web/system/controller/core/UserController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/UserController.java#L581

```text
  578       * @return
  579       */
  580
  581      @RequestMapping(params = "saveUser")
  582      @ResponseBody
  583      public AjaxJson saveUser(HttpServletRequest req, TSUser user) {
  584          String message = null;
```

2. `src/main/java/org/jeecgframework/web/system/controller/core/UserController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/UserController.java#L587

```text
  584          String message = null;
  585          AjaxJson j = new AjaxJson();
  586          // [non-English text removed]
  587          String roleid = oConvertUtils.getString(req.getParameter("roleid"));
  588          String password = oConvertUtils.getString(req.getParameter("password"));
  589          if (StringUtil.isNotEmpty(user.getId())) {
  590              TSUser users = systemService.getEntity(TSUser.class, user.getId());
```

3. `src/main/java/org/jeecgframework/web/system/controller/core/UserController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/UserController.java#L595

```text
  592              users.setOfficePhone(user.getOfficePhone());
  593              users.setMobilePhone(user.getMobilePhone());
  594
  595              systemService.executeSql("delete from t_s_user_org where user_id=?", user.getId());
  596              saveUserOrgList(req, user);
  597  //            users.setTSDepart(user.getTSDepart());
  598
  599              users.setRealName(user.getRealName());
  600              users.setStatus(Globals.User_Normal);
  601              users.setActivitiSync(user.getActivitiSync());
  602              systemService.updateEntitie(users);
  603              List<TSRoleUser> ru = systemService.findByProperty(TSRoleUser.class, "TSUser.id", user.getId());
  604              systemService.deleteAllEntitie(ru);
  605              message = "[non-English text removed]: " + users.getUserName() + "[non-English text removed]";
  606              if (StringUtil.isNotEmpty(roleid)) {
  607                  saveRoleUser(users, roleid);
  608              }
  609              systemService.addLog(message, Globals.Log_Type_UPDATE, Globals.Log_Leavel_INFO);
  610          } else {
```

4. `src/main/java/org/jeecgframework/web/system/controller/core/UserController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/UserController.java#L643

```text
  640       * @param request request
  641       * @param user    user
  642       */
  643      private void saveUserOrgList(HttpServletRequest request, TSUser user) {
  644          String orgIds = oConvertUtils.getString(request.getParameter("orgIds"));
  645
  646          List<TSUserOrg> userOrgList = new ArrayList<TSUserOrg>();
  647          List<String> orgIdList = extractIdListByComma(orgIds);
  648          for (String orgId : orgIdList) {
  649              TSDepart depart = new TSDepart();
  650              depart.setId(orgId);
  651
  652              TSUserOrg userOrg = new TSUserOrg();
  653              userOrg.setTsUser(user);
  654              userOrg.setTsDepart(depart);
  655
  656              userOrgList.add(userOrg);
  657          }
  658          if (!userOrgList.isEmpty()) {
  659              systemService.batchSave(userOrgList);
  660          }
  661      }
  662
  663
```

5. `src/main/java/org/jeecgframework/web/system/controller/core/UserController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/system/controller/core/UserController.java#L664

```text
  661      }
  662
  663
  664      protected void saveRoleUser(TSUser user, String roleidstr) {
  665          String[] roleids = roleidstr.split(",");
  666          for (int i = 0; i < roleids.length; i++) {
  667              TSRoleUser rUser = new TSRoleUser();
  668              TSRole role = systemService.getEntity(TSRole.class, roleids[i]);
  669              rUser.setTSRole(role);
  670              rUser.setTSUser(user);
  671              systemService.save(rUser);
  672
  673          }
  674      }
  675
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

Published reference: https://aibot88.github.io/CVERequest/JEEWMS/issue1.html
