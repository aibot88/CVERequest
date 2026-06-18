---
title: "JSH_ERP issue5: Unauthorized Role Capability Modification via `/role/*`"
description: "JSH_ERP has a missing authorization vulnerability in `POST /role/add`, `PUT /role/update`, `POST /role/batchSetStatus`, `DELETE /role/delete`, `DELETE /role/deleteBatch`. A user can weaken price masking, change data-scope type, enable disabled roles, or delete roles. This can grant broader business data visibility and alter authorization behavior for all users assigned to the affected role"
tags:
  - JSH_ERP
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JSH_ERP has a missing authorization vulnerability in `POST /role/add`, `PUT /role/update`, `POST /role/batchSetStatus`, `DELETE /role/delete`, `DELETE /role/deleteBatch`. A user can weaken price masking, change data-scope type, enable disabled roles, or delete roles. This can grant broader business data visibility and alter authorization behavior for all users assigned to the affected role

- Attack precondition: Any authenticated user
- Affected endpoint: ``POST /role/add`, `PUT /role/update`, `POST /role/batchSetStatus`, `DELETE /role/delete`, `DELETE /role/deleteBatch``
- Affected authorization property: ``Role.type`, `Role.priceLimit`, `Role.enabled`, `Role.deleteFlag``
- Security impact: A user can weaken price masking, change data-scope type, enable disabled roles, or delete roles. This can grant broader business data visibility and alter authorization behavior for all users assigned to the affected role

### 1.2 Exploit path

The attacker creates or updates role records with chosen `type` and `priceLimit`, or enables/disables/deletes role records. Existing users bound to those roles inherit the modified data scope and price visibility behavior

### 1.3 Key code evidence

1. `jshERP-boot/src/main/java/com/jsh/erp/controller/RoleController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/RoleController.java#L68

```text
   65          return getDataTable(list);
   66      }
   67  
   68      @PostMapping(value = "/add")
   69      @ApiOperation(value = "新增")
   70      public String addResource(@RequestBody JSONObject obj, HttpServletRequest request)throws Exception {
   71          Map<String, Object> objectMap = new HashMap<>();
   72          int insert = roleService.insertRole(obj, request);
   73          return returnStr(objectMap, insert);
   74      }
   75  
   76      @PutMapping(value = "/update")
   77      @ApiOperation(value = "修改")
   78      public String updateResource(@RequestBody JSONObject obj, HttpServletRequest request)throws Exception {
   79          Map<String, Object> objectMap = new HashMap<>();
   80          int update = roleService.updateRole(obj, request);
   81          return returnStr(objectMap, update);
   82      }
```

2. `jshERP-boot/src/main/java/com/jsh/erp/service/RoleService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/RoleService.java#L121

```text
  118      }
  119  
  120      @Transactional(value = "transactionManager", rollbackFor = Exception.class)
  121      public int insertRole(JSONObject obj, HttpServletRequest request)throws Exception {
  122          Role role = JSONObject.parseObject(obj.toJSONString(), Role.class);
  123          int result=0;
  124          try{
  125              role.setEnabled(true);
  126              result=roleMapper.insertSelective(role);
  127              logService.insertLog("角色",
  128                      new StringBuffer(BusinessConstants.LOG_OPERATION_TYPE_ADD).append(role.getName()).toString(), request);
  129          }catch(Exception e){
  130              JshException.writeFail(logger, e);
  131          }
  132          return result;
  133      }
  134  
  135      @Transactional(value = "transactionManager", rollbackFor = Exception.class)
  136      public int updateRole(JSONObject obj, HttpServletRequest request) throws Exception{
  137          Role role = JSONObject.parseObject(obj.toJSONString(), Role.class);
  138          int result=0;
  139          try{
  140              result=roleMapper.updateByPrimaryKeySelective(role);
  141              logService.insertLog("角色",
  142                      new StringBuffer(BusinessConstants.LOG_OPERATION_TYPE_EDIT).append(role.getName()).toString(), request);
  143          }catch(Exception e){
```

3. `jshERP-boot/src/main/java/com/jsh/erp/service/RoleService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/RoleService.java#L216

```text
  213      }
  214  
  215      @Transactional(value = "transactionManager", rollbackFor = Exception.class)
  216      public int batchSetStatus(Boolean status, String ids)throws Exception {
  217          logService.insertLog("角色",
  218                  new StringBuffer(BusinessConstants.LOG_OPERATION_TYPE_ENABLED).toString(),
  219                  ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest());
  220          List<Long> roleIds = StringUtil.strToLongList(ids);
  221          Role role = new Role();
  222          role.setEnabled(status);
  223          RoleExample example = new RoleExample();
  224          example.createCriteria().andIdIn(roleIds);
  225          int result=0;
  226          try{
  227              result = roleMapper.updateByExampleSelective(role, example);
  228          }catch(Exception e){
  229              JshException.writeFail(logger, e);
  230          }
  231          return result;
```

4. `jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java`

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

5. `jshERP-boot/src/main/java/com/jsh/erp/service/RoleService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/RoleService.java#L240

```text
  237       * @param type
  238       * @return
  239       */
  240      public Object parseHomePriceByLimit(BigDecimal price, String type, String priceLimit, String emptyInfo, HttpServletRequest request) throws Exception {
  241          if(StringUtil.isNotEmpty(priceLimit)) {
  242              if("buy".equals(type) && priceLimit.contains("1")) {
  243                  return emptyInfo;
  244              }
  245              if("retail".equals(type) && priceLimit.contains("2")) {
  246                  return emptyInfo;
  247              }
  248              if("sale".equals(type) && priceLimit.contains("3")) {
  249                  return emptyInfo;
  250              }
  251          }
  252          return price;
  253      }
  254  
  255      /**
  256       * 根据权限进行屏蔽价格-单据
  257       * @param price
  258       * @param billCategory
  259       * @param priceLimit
  260       * @param request
  261       * @return
  262       * @throws Exception
  263       */
  264      public BigDecimal parseBillPriceByLimit(BigDecimal price, String billCategory, String priceLimit, HttpServletRequest request) throws Exception {
  265          if(StringUtil.isNotEmpty(priceLimit)) {
  266              if("buy".equals(billCategory) && priceLimit.contains("4")) {
  267                  return BigDecimal.ZERO;
  268              }
  269              if("retail".equals(billCategory) && priceLimit.contains("5")) {
  270                  return BigDecimal.ZERO;
  271              }
  272              if("sale".equals(billCategory) && priceLimit.contains("6")) {
  273                  return BigDecimal.ZERO;
  274              }
  275          }
  276          return price;
  277      }
  278  
  279      /**
  280       * 根据权限进行屏蔽价格-物料
  281       * @param price
  282       * @param type
  283       * @return
  284       */
  285      public Object parseMaterialPriceByLimit(BigDecimal price, String type, String emptyInfo, HttpServletRequest request) throws Exception {
  286          Long userId = userService.getUserId(request);
  287          String priceLimit = userService.getRoleTypeByUserId(userId).getPriceLimit();
  288          if(StringUtil.isNotEmpty(priceLimit)) {
  289              if("buy".equals(type) && priceLimit.contains("4")) {
  290                  return emptyInfo;
  291              }
  292              if("retail".equals(type) && priceLimit.contains("5")) {
  293                  return emptyInfo;
  294              }
  295              if("sale".equals(type) && priceLimit.contains("6")) {
  296                  return emptyInfo;
  297              }
  298          }
  299          return price;
  300      }
  301  
  302      public String getCurrentPriceLimit(HttpServletRequest request) throws Exception {
  303          Long userId = userService.getUserId(request);
  304          return userService.getRoleTypeByUserId(userId).getPriceLimit();
  305      }
  306  }
```


## 2. Existing checks and why they fail

- `insertRole` forces `enabled=true`, but does not restrict `type`, `priceLimit`, tenant, or role management authority.
- No role-management permission check exists.
- No field-level ceiling prevents privilege expansion.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Restrict role CRUD to tenant administrators or dedicated role managers. Enforce field-level constraints for `type`, `priceLimit`, and enabled/deleted state. Prevent modification of roles outside the caller's management scope

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JSH_ERP/issue5.html
