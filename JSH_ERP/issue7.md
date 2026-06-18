---
title: "JSH_ERP issue7: Authorization Relationship Disclosure via Checked/Value Helper Endpoints"
description: "JSH_ERP has a missing authorization vulnerability in `GET /role/findUserRole`, `GET /depot/findUserDepot`, `GET /supplier/getUserCustomerValue`, `GET /user/getUserWithChecked`. The endpoints reveal authorization relationships such as which role a user has, which warehouses a user can access, which customers are assigned, or which users are linked to a relationship value"
tags:
  - JSH_ERP
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JSH_ERP has a missing authorization vulnerability in `GET /role/findUserRole`, `GET /depot/findUserDepot`, `GET /supplier/getUserCustomerValue`, `GET /user/getUserWithChecked`. The endpoints reveal authorization relationships such as which role a user has, which warehouses a user can access, which customers are assigned, or which users are linked to a relationship value

- Attack precondition: Any authenticated user
- Affected endpoint: ``GET /role/findUserRole`, `GET /depot/findUserDepot`, `GET /supplier/getUserCustomerValue`, `GET /user/getUserWithChecked``
- Affected authorization property: ``UserBusiness` relationship existence and values for roles, warehouses, customers, and users`
- Security impact: The endpoints reveal authorization relationships such as which role a user has, which warehouses a user can access, which customers are assigned, or which users are linked to a relationship value

### 1.2 Exploit path

The attacker supplies `UBType`, `UBKeyId`, or `UBValue` to helper endpoints. The backend reads relationship values and returns checked state or raw id arrays

### 1.3 Key code evidence

1. `jshERP-boot/src/main/java/com/jsh/erp/controller/RoleController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/RoleController.java#L119

```text
  116       * @param request
  117       * @return
  118       */
  119      @GetMapping(value = "/findUserRole")
  120      @ApiOperation(value = "[non-English text removed]")
  121      public JSONArray findUserRole(@RequestParam("UBType") String type, @RequestParam("UBKeyId") String keyId,
  122                                    HttpServletRequest request)throws Exception {
  123          JSONArray arr = new JSONArray();
  124          try {
  125              //[non-English text removed]
  126              String ubValue = userBusinessService.getUBValueByTypeAndKeyId(type, keyId);
  127              List<Role> dataList = roleService.findUserRole();
  128              if (null != dataList) {
  129                  for (Role role : dataList) {
  130                      JSONObject item = new JSONObject();
  131                      item.put("id", role.getId());
  132                      item.put("text", role.getName());
  133                      Boolean flag = ubValue.contains("[" + role.getId().toString() + "]");
  134                      if (flag) {
  135                          item.put("checked", true);
  136                      }
  137                      arr.add(item);
  138                  }
  139              }
  140          } catch (Exception e) {
```

2. `jshERP-boot/src/main/java/com/jsh/erp/controller/DepotController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/DepotController.java#L159

```text
  156       * @param request
  157       * @return
  158       */
  159      @GetMapping(value = "/findUserDepot")
  160      @ApiOperation(value = "[non-English text removed]")
  161      public JSONArray findUserDepot(@RequestParam("UBType") String type, @RequestParam("UBKeyId") String keyId,
  162                                   HttpServletRequest request) throws Exception{
  163          JSONArray arr = new JSONArray();
  164          try {
  165              //[non-English text removed]
  166              String ubValue = userBusinessService.getUBValueByTypeAndKeyId(type, keyId);
  167              List<Depot> dataList = depotService.findUserDepot();
  168              //[non-English text removed]json[non-English text removed]
  169              JSONObject outer = new JSONObject();
  170              outer.put("id", 0);
  171              outer.put("key", 0);
  172              outer.put("value", 0);
  173              outer.put("title", "[non-English text removed]");
  174              outer.put("attributes", "[non-English text removed]");
  175              //[non-English text removed]json[non-English text removed]
  176              JSONArray dataArray = new JSONArray();
  177              if (null != dataList) {
  178                  for (Depot depot : dataList) {
  179                      JSONObject item = new JSONObject();
  180                      item.put("id", depot.getId());
  181                      item.put("key", depot.getId());
  182                      item.put("value", depot.getId());
  183                      item.put("title", depot.getName());
  184                      item.put("attributes", depot.getName());
  185                      Boolean flag = ubValue.contains("[" + depot.getId().toString() + "]");
  186                      if (flag) {
  187                          item.put("checked", true);
  188                      }
  189                      dataArray.add(item);
  190                  }
  191              }
  192              outer.put("children", dataArray);
```

3. `jshERP-boot/src/main/java/com/jsh/erp/controller/SupplierController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/SupplierController.java#L342

```text
  339       * @param request
  340       * @return
  341       */
  342      @GetMapping(value = "/getUserCustomerValue")
  343      @ApiOperation(value = "[non-English text removed]")
  344      public JSONObject getUserCustomerValue(@RequestParam("UBType") String type, @RequestParam("UBKeyId") String keyId,
  345                                             HttpServletRequest request) throws Exception{
  346          JSONObject obj = new JSONObject();
  347          try {
  348              //[non-English text removed]
  349              String ubValue = userBusinessService.getUBValueByTypeAndKeyId(type, keyId);
  350              if(StringUtil.isNotEmpty(ubValue)) {
  351                  String ubStr = ubValue.substring(1, ubValue.length()-1);
  352                  String [] ubArr = ubStr.split("]\\[");
  353                  Long[] ubLongArray = new Long[ubArr.length];
  354                  for (int i = 0; i < ubArr.length; i++) {
  355                      ubLongArray[i] = Long.parseLong(ubArr[i]);
  356                  }
  357                  obj.put("data", ubLongArray);
  358              } else {
  359                  obj.put("data", null);
  360              }
  361              obj.put("code", 200);
  362          } catch (Exception e) {
  363              obj.put("code", 500);
  364              obj.put("data", "[non-English text removed]");
  365              logger.error(e.getMessage(), e);
  366          }
  367          return obj;
  368      }
  369
  370      /**
```

4. `jshERP-boot/src/main/java/com/jsh/erp/controller/UserController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/UserController.java#L465

```text
  462       * @param request
  463       * @return
  464       */
  465      @GetMapping(value = "/getUserWithChecked")
  466      @ApiOperation(value = "[non-English text removed]")
  467      public JSONArray getUserWithChecked(@RequestParam("UBType") String type, @RequestParam("UBValue") String oneValue,
  468                                    HttpServletRequest request) throws Exception{
  469          JSONArray arr = new JSONArray();
  470          try {
  471              //[non-English text removed]
  472              List<Long> keyIdList = userBusinessService.getUBKeyIdByTypeAndOneValue(type, oneValue);
  473              Map<Long, Long> keyIdMap = keyIdList.stream().collect(Collectors.toMap(Function.identity(),Function.identity()));
  474              List<User> dataList = userService.getUser(request);
  475              //[non-English text removed]json[non-English text removed]
  476              JSONObject outer = new JSONObject();
  477              outer.put("id", 0);
  478              outer.put("key", 0);
  479              outer.put("value", 0);
  480              outer.put("title", "[non-English text removed]");
  481              outer.put("attributes", "[non-English text removed]");
  482              //[non-English text removed]json[non-English text removed]
  483              JSONArray dataArray = new JSONArray();
  484              if (null != dataList) {
  485                  for (User user : dataList) {
  486                      JSONObject item = new JSONObject();
  487                      item.put("id", user.getId());
  488                      item.put("key", user.getId());
  489                      item.put("value", user.getId());
  490                      item.put("title", user.getLoginName() + "(" + user.getUsername() + ")");
  491                      item.put("attributes", user.getLoginName());
  492                      if (keyIdMap.get(user.getId())!=null) {
  493                          item.put("checked", true);
  494                      }
  495                      dataArray.add(item);
  496                  }
  497              }
  498              outer.put("children", dataArray);
  499              arr.add(outer);
  500          } catch (Exception e) {
  501              logger.error(e.getMessage(), e);
  502          }
```

5. `jshERP-boot/src/main/java/com/jsh/erp/service/UserBusinessService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserBusinessService.java#L135

```text
  132          return list;
  133      }
  134
  135      public String getUBValueByTypeAndKeyId(String type, String keyId) throws Exception {
  136          String ubValue = "";
  137          List<UserBusiness> ubList = getBasicData(keyId, type);
  138          if(ubList!=null && ubList.size()>0) {
  139              ubValue = ubList.get(0).getValue();
  140          }
  141          return ubValue;
  142      }
  143
  144      public Long checkIsValueExist(String type, String keyId)throws Exception {
```


## 2. Existing checks and why they fail

- Authentication is the only generic gate. - Returning `checked` rather than raw `value` still leaks authorization relationship existence. - No current-user binding or management-scope validation exists

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Restrict these helper endpoints to authorized management workflows. Validate allowed `UBType`, target object scope, and whether the caller can inspect the requested relationship

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JSH_ERP/issue7.html
