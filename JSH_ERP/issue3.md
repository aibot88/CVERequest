---
title: "JSH_ERP issue3: Unauthorized Write of Authorization Relationships via `/userBusiness/*`"
description: "JSH_ERP has a missing authorization vulnerability in `POST /userBusiness/add`, `PUT /userBusiness/update`, `DELETE /userBusiness/delete`, `DELETE /userBusiness/deleteBatch`, `POST /userBusiness/updateBtnStr`, `POST /userBusiness/updateOneValueByKeyIdAndType`. A low-privileged user can modify role assignments, menu/function mappings, button permissions, warehouse access, or customer access. This can directly change authorization state and expand the attacker's effective permissions"
tags:
  - JSH_ERP
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JSH_ERP has a missing authorization vulnerability in `POST /userBusiness/add`, `PUT /userBusiness/update`, `DELETE /userBusiness/delete`, `DELETE /userBusiness/deleteBatch`, `POST /userBusiness/updateBtnStr`, `POST /userBusiness/updateOneValueByKeyIdAndType`. A low-privileged user can modify role assignments, menu/function mappings, button permissions, warehouse access, or customer access. This can directly change authorization state and expand the attacker's effective permissions

- Attack precondition: Any authenticated user
- Affected endpoint: ``POST /userBusiness/add`, `PUT /userBusiness/update`, `DELETE /userBusiness/delete`, `DELETE /userBusiness/deleteBatch`, `POST /userBusiness/updateBtnStr`, `POST /userBusiness/updateOneValueByKeyIdAndType``
- Affected authorization property: ``UserBusiness.type`, `keyId`, `value`, `btnStr`, `deleteFlag``
- Security impact: A low-privileged user can modify role assignments, menu/function mappings, button permissions, warehouse access, or customer access. This can directly change authorization state and expand the attacker's effective permissions

### 1.2 Exploit path

The attacker submits crafted `UserBusiness` JSON or endpoint-specific parameters to create, update, delete, or mutate relationship rows. These rows encode `UserRole`, `RoleFunctions`, `UserDepot`, `UserCustomer`, and related authorization bindings

### 1.3 Key code evidence

1. `jshERP-boot/src/main/java/com/jsh/erp/controller/UserBusinessController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/UserBusinessController.java#L50

```text
   47          }
   48      }
   49  
   50      @PostMapping(value = "/add")
   51      @ApiOperation(value = "新增")
   52      public String addResource(@RequestBody JSONObject obj, HttpServletRequest request)throws Exception {
   53          Map<String, Object> objectMap = new HashMap<>();
   54          int insert = userBusinessService.insertUserBusiness(obj, request);
   55          return returnStr(objectMap, insert);
   56      }
   57  
   58      @PutMapping(value = "/update")
   59      @ApiOperation(value = "修改")
   60      public String updateResource(@RequestBody JSONObject obj, HttpServletRequest request)throws Exception {
   61          Map<String, Object> objectMap = new HashMap<>();
   62          int update = userBusinessService.updateUserBusiness(obj, request);
   63          return returnStr(objectMap, update);
   64      }
   65  
   66      @DeleteMapping(value = "/delete")
   67      @ApiOperation(value = "删除")
   68      public String deleteResource(@RequestParam("id") Long id, HttpServletRequest request)throws Exception {
   69          Map<String, Object> objectMap = new HashMap<>();
   70          int delete = userBusinessService.deleteUserBusiness(id, request);
   71          return returnStr(objectMap, delete);
   72      }
   73  
   74      @DeleteMapping(value = "/deleteBatch")
   75      @ApiOperation(value = "批量删除")
   76      public String batchDeleteResource(@RequestParam("ids") String ids, HttpServletRequest request)throws Exception {
   77          Map<String, Object> objectMap = new HashMap<>();
   78          int delete = userBusinessService.batchDeleteUserBusiness(ids, request);
   79          return returnStr(objectMap, delete);
   80      }
   81  
   82      @GetMapping(value = "/checkIsNameExist")
```

2. `jshERP-boot/src/main/java/com/jsh/erp/service/UserBusinessService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserBusinessService.java#L62

```text
   59      }
   60  
   61      @Transactional(value = "transactionManager", rollbackFor = Exception.class)
   62      public int insertUserBusiness(JSONObject obj, HttpServletRequest request) throws Exception {
   63          UserBusiness userBusiness = JSONObject.parseObject(obj.toJSONString(), UserBusiness.class);
   64          int result=0;
   65          try{
   66              String value = userBusiness.getValue();
   67              String newValue = value.replaceAll(",","\\]\\[");
   68              newValue = newValue.replaceAll("\\[0\\]","").replaceAll("\\[\\]","");
   69              userBusiness.setValue(newValue);
   70              result=userBusinessMapper.insertSelective(userBusiness);
   71              logService.insertLog("关联关系", BusinessConstants.LOG_OPERATION_TYPE_ADD, request);
   72          }catch(Exception e){
   73              JshException.writeFail(logger, e);
```

3. `jshERP-boot/src/main/java/com/jsh/erp/service/UserBusinessService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserBusinessService.java#L79

```text
   76      }
   77  
   78      @Transactional(value = "transactionManager", rollbackFor = Exception.class)
   79      public int updateUserBusiness(JSONObject obj, HttpServletRequest request) throws Exception {
   80          UserBusiness userBusiness = JSONObject.parseObject(obj.toJSONString(), UserBusiness.class);
   81          int result=0;
   82          try{
   83              String value = userBusiness.getValue();
   84              String newValue = value.replaceAll(",","\\]\\[");
   85              newValue = newValue.replaceAll("\\[0\\]","").replaceAll("\\[\\]","");
   86              userBusiness.setValue(newValue);
   87              result=userBusinessMapper.updateByPrimaryKeySelective(userBusiness);
   88              logService.insertLog("关联关系", BusinessConstants.LOG_OPERATION_TYPE_EDIT, request);
   89          }catch(Exception e){
   90              JshException.writeFail(logger, e);
```

4. `jshERP-boot/src/main/java/com/jsh/erp/service/UserBusinessService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserBusinessService.java#L162

```text
  159      }
  160  
  161      @Transactional(value = "transactionManager", rollbackFor = Exception.class)
  162      public int updateBtnStr(String keyId, String type, String btnStr) throws Exception{
  163          logService.insertLog("关联关系",
  164                  new StringBuffer(BusinessConstants.LOG_OPERATION_TYPE_EDIT).append("角色的按钮权限").toString(),
  165                  ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest());
  166          UserBusiness userBusiness = new UserBusiness();
  167          userBusiness.setBtnStr(btnStr);
  168          UserBusinessExample example = new UserBusinessExample();
  169          example.createCriteria().andKeyIdEqualTo(keyId).andTypeEqualTo(type);
  170          int result=0;
  171          try{
  172              result=  userBusinessMapper.updateByExampleSelective(userBusiness, example);
  173          }catch(Exception e){
  174              JshException.writeFail(logger, e);
  175          }
```

5. `jshERP-boot/src/main/java/com/jsh/erp/service/UserBusinessService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserBusinessService.java#L183

```text
  180          return userBusinessMapperEx.getUBKeyIdByTypeAndOneValue(type, oneValue);
  181      }
  182  
  183      public int updateOneValueByKeyIdAndType(String type, JSONArray keyIdArr, String oneValue) {
  184          int res = 0;
  185          try {
  186              Map<String, String> keyIdMap = new HashMap<>();
  187              List<UserBusiness> oldUbList = userBusinessMapperEx.getOldListByType(type);
  188              for(Object keyIdObj: keyIdArr) {
  189                  String keyId = keyIdObj.toString();
  190                  keyIdMap.put(keyId, keyId);
  191                  List<UserBusiness> ubList = userBusinessMapperEx.getBasicDataByKeyIdAndType(keyId, type);
  192                  if(ubList.size()>0) {
  193                      String valueStr = ubList.get(0).getValue();
  194                      Boolean flag = valueStr.contains("[" + oneValue + "]");
  195                      if(flag) {
  196                          //存在则忽略
  197                      } else {
  198                          //不存在则追加并更新
  199                          valueStr = valueStr + "[" + oneValue + "]";
  200                          UserBusiness userBusiness = new UserBusiness();
  201                          userBusiness.setId(ubList.get(0).getId());
  202                          userBusiness.setValue(valueStr);
  203                          userBusinessMapper.updateByPrimaryKeySelective(userBusiness);
  204                      }
  205                  } else {
  206                      //新增数据
  207                      UserBusiness userBusiness = new UserBusiness();
  208                      userBusiness.setType(type);
  209                      userBusiness.setKeyId(keyId);
  210                      userBusiness.setValue("[" + oneValue + "]");
  211                      userBusinessMapper.insertSelective(userBusiness);
  212                  }
  213              }
  214              //检查被移除的keyId
  215              for(UserBusiness item: oldUbList) {
  216                  String oldValue = item.getValue();
  217                  String oldkeyId = item.getKeyId();
  218                  if(keyIdMap.get(oldkeyId) == null) {
  219                      //处理被删除的keyId
  220                      String valueStr = "[" + oneValue + "]";
  221                      if(oldValue.equals(valueStr)) {
  222                          //说明value里面只有一条数据，需要进行逻辑删除
  223                          UserBusiness userBusiness = new UserBusiness();
  224                          userBusiness.setId(item.getId());
  225                          userBusiness.setDeleteFlag("1");
  226                          userBusinessMapper.updateByPrimaryKeySelective(userBusiness);
  227                      } else {
  228                          //多条进行替换后再更新
  229                          String newValue = oldValue.replace(valueStr, "");
  230                          UserBusiness userBusiness = new UserBusiness();
  231                          userBusiness.setId(item.getId());
  232                          userBusiness.setValue(newValue);
  233                          userBusinessMapper.updateByPrimaryKeySelective(userBusiness);
  234                      }
  235                  }
  236              }
  237              res = 1;
  238          } catch (Exception e) {
  239              res = 0;
  240              logger.error(e.getMessage(), e);
```

6. `jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java#L832

```text
  829              }
  830              role = roleService.getRoleWithoutTenant(Long.parseLong(roleId));
  831          }
  832          return role;
  833      }
  834  
  835      /**
  836       * 获取用户id
  837       * @param request
  838       * @return
  839       */
  840      public Long getUserId(HttpServletRequest request) throws Exception{
  841          Object userIdObj = redisService.getObjectFromSessionByKey(request,"userId");
  842          Long userId = null;
  843          if(userIdObj != null) {
  844              userId = Long.parseLong(userIdObj.toString());
  845          }
  846          return userId;
  847      }
  848  
  849      /**
  850       * 用户的按钮权限
  851       * @param userId
```

7. `jshERP-boot/src/main/java/com/jsh/erp/service/DepotService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/DepotService.java#L317

```text
  314  
  315      public JSONArray findDepotByCurrentUser() throws Exception {
  316          JSONArray arr = new JSONArray();
  317          String type = "UserDepot";
  318          Long userId = userService.getCurrentUser().getId();
  319          List<Depot> dataList = findUserDepot();
  320          //开始拼接json数据
  321          if (null != dataList) {
  322              boolean depotFlag = systemConfigService.getDepotFlag();
  323              if(depotFlag) {
  324                  List<UserBusiness> list = userBusinessService.getBasicData(userId.toString(), type);
  325                  if(list!=null && list.size()>0) {
  326                      String depotStr = list.get(0).getValue();
  327                      if(StringUtil.isNotEmpty(depotStr)){
  328                          depotStr = depotStr.replaceAll("\\[", "").replaceAll("]", ",");
  329                          String[] depotArr = depotStr.split(",");
  330                          for (Depot depot : dataList) {
  331                              for(String depotId: depotArr) {
  332                                  if(depot.getId() == Long.parseLong(depotId)){
  333                                      JSONObject item = new JSONObject();
  334                                      item.put("id", depot.getId());
  335                                      item.put("depotName", depot.getName());
  336                                      item.put("isDefault", depot.getIsDefault());
  337                                      arr.add(item);
  338                                  }
  339                              }
  340                          }
```


## 2. Existing checks and why they fail

- No authorization check ensures the caller can manage the target user, role, warehouse, customer, or function.
- No role ceiling or function ceiling is enforced in these write endpoints.
- No field whitelist prevents writing permission-sensitive columns.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Do not expose generic `UserBusiness` CRUD to ordinary users. Replace it with domain-specific management operations that validate caller role, target scope, assignable role/function ceiling, and tenant boundary

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JSH_ERP/issue3.html
