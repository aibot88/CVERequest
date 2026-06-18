---
title: "JSH_ERP issue6: Target User Menu Permission Disclosure via `/function/findMenuByPNumber`"
description: "JSH_ERP has a missing authorization vulnerability in `POST /function/findMenuByPNumber`. The endpoint discloses another user's effective menu permissions and role-derived function access. This is authorization-state leakage"
tags:
  - JSH_ERP
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JSH_ERP has a missing authorization vulnerability in `POST /function/findMenuByPNumber`. The endpoint discloses another user's effective menu permissions and role-derived function access. This is authorization-state leakage

- Attack precondition: Any authenticated user who knows or can guess a target `userId`
- Affected endpoint: ``POST /function/findMenuByPNumber``
- Affected authorization property: `target user's `UserRole` and `RoleFunctions` derived menu permissions`
- Security impact: The endpoint discloses another user's effective menu permissions and role-derived function access. This is authorization-state leakage

### 1.2 Exploit path

The attacker sends a request body with arbitrary `userId`. The endpoint reads that user's `UserRole`, then reads the role's `RoleFunctions`, and returns the derived menu tree

### 1.3 Key code evidence

1. `jshERP-boot/src/main/java/com/jsh/erp/controller/FunctionController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/FunctionController.java#L143

```text
  140       * @return
  141       * @throws Exception
  142       */
  143      @PostMapping(value = "/findMenuByPNumber")
  144      @ApiOperation(value = "根据父编号查询菜单")
  145      public JSONArray findMenuByPNumber(@RequestBody JSONObject jsonObject,
  146                                HttpServletRequest request)throws Exception {
  147          String pNumber = jsonObject.getString("pNumber");
  148          String userId = jsonObject.getString("userId");
  149          //存放数据json数组
  150          JSONArray dataArray = new JSONArray();
  151          try {
  152              Long roleId = 0L;
```

2. `jshERP-boot/src/main/java/com/jsh/erp/controller/FunctionController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/FunctionController.java#L154

```text
  151          try {
  152              Long roleId = 0L;
  153              String fc = "";
  154              List<UserBusiness> roleList = userBusinessService.getBasicData(userId, "UserRole");
  155              if(roleList!=null && roleList.size()>0){
  156                  String value = roleList.get(0).getValue();
  157                  if(StringUtil.isNotEmpty(value)){
  158                      String roleIdStr = value.replace("[", "").replace("]", "");
  159                      roleId = Long.parseLong(roleIdStr);
  160                  }
  161              }
  162              //当前用户所拥有的功能列表，格式如：[1][2][5]
  163              List<UserBusiness> funList = userBusinessService.getBasicData(roleId.toString(), "RoleFunctions");
  164              if(funList!=null && funList.size()>0){
  165                  fc = funList.get(0).getValue();
  166              }
  167              //获取系统配置信息-是否开启多级审核
  168              String approvalFlag = "0";
```

3. `jshERP-boot/src/main/java/com/jsh/erp/controller/FunctionController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/FunctionController.java#L174

```text
  171                  approvalFlag = list.get(0).getMultiLevelApprovalFlag();
  172              }
  173  
  174              List<Function> dataList = functionService.getRoleFunction(pNumber);
  175              if (dataList.size() != 0) {
  176                  User userInfo = userService.getCurrentUser();
  177                  //获取当前用户所属的租户所拥有的功能id的map
  178                  Map<Long, Long> funIdMap = functionService.getCurrentTenantFunIdMap();
  179                  dataArray = getMenuByFunction(dataList, fc, approvalFlag, funIdMap, userInfo);
  180                  //增加首页菜单项
  181                  JSONObject homeItem = new JSONObject();
  182                  homeItem.put("id", 0);
  183                  homeItem.put("text", "首页");
  184                  homeItem.put("icon", "home");
  185                  homeItem.put("url", "/dashboard/analysis");
  186                  homeItem.put("component", "/layouts/TabLayout");
  187                  dataArray.add(0,homeItem);
  188              }
  189          } catch (DataAccessException e) {
  190              logger.error(">>>>>>>>>>>>>>>>>>>查找异常", e);
  191          }
  192          return dataArray;
  193      }
  194  
  195      public JSONArray getMenuByFunction(List<Function> dataList, String fc, String approvalFlag, Map<Long, Long> funIdMap, User userInfo) throws Exception {
  196          JSONArray dataArray = new JSONArray();
  197          for (Function function : dataList) {
  198              //如果不是超管也不是租户就需要校验，防止分配下级用户的功能权限，大于租户的权限
  199              if("admin".equals(userInfo.getLoginName()) || userInfo.getId().equals(userInfo.getTenantId()) || funIdMap.get(function.getId())!=null) {
  200                  //如果关闭多级审核，遇到任务审核菜单直接跳过
  201                  if("0".equals(approvalFlag) && "/workflow".equals(function.getUrl())) {
  202                      continue;
  203                  }
  204                  JSONObject item = new JSONObject();
  205                  List<Function> newList = functionService.getRoleFunction(function.getNumber());
  206                  item.put("id", function.getId());
  207                  item.put("text", function.getName());
  208                  item.put("icon", function.getIcon());
  209                  item.put("url", function.getUrl());
  210                  item.put("component", function.getComponent());
  211                  if (newList.size()>0) {
  212                      JSONArray childrenArr = getMenuByFunction(newList, fc, approvalFlag, funIdMap, userInfo);
  213                      if(childrenArr.size()>0) {
  214                          item.put("children", childrenArr);
  215                          dataArray.add(item);
  216                      }
  217                  } else {
  218                      if (fc.indexOf("[" + function.getId().toString() + "]") != -1) {
  219                          dataArray.add(item);
  220                      }
  221                  }
  222              }
  223          }
```


## 2. Existing checks and why they fail

- The login filter authenticates the caller only.
- Tenant function-map filtering limits returned functions to the current tenant's function set, but does not authorize reading the target user's permission state.
- No check enforces `body.userId == currentUser.id` or that the caller manages the target user.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

For normal menu loading, ignore request-supplied `userId` and use the session user. For administrative preview, require management permission and target-user scope validation

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JSH_ERP/issue6.html
