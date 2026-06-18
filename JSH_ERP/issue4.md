---
title: "JSH_ERP issue4: Unauthorized User Role and Organization Binding via `/user/addUser` and `/user/updateUser`"
description: "JSH_ERP has a missing authorization vulnerability in `POST /user/addUser`, `PUT /user/updateUser`. A low-privileged user can assign a higher role to themselves or others and move users into organizations that affect data visibility and business permissions"
tags:
  - JSH_ERP
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JSH_ERP has a missing authorization vulnerability in `POST /user/addUser`, `PUT /user/updateUser`. A low-privileged user can assign a higher role to themselves or others and move users into organizations that affect data visibility and business permissions

- Attack precondition: Any authenticated user. For user creation, tenant user count must not exceed the configured limit
- Affected endpoint: ``POST /user/addUser`, `PUT /user/updateUser``
- Affected authorization property: ``UserBusiness.value` for `UserRole`, `OrgaUserRel.orgaId`, `OrgaUserRel.userId``
- Security impact: A low-privileged user can assign a higher role to themselves or others and move users into organizations that affect data visibility and business permissions

### 1.2 Exploit path

The attacker submits `roleId` and `orgaId` in the user-management request body. The service writes `roleId` into the target user's `UserRole` relationship and creates or updates the target user's organization relationship

### 1.3 Key code evidence

1. `jshERP-boot/src/main/java/com/jsh/erp/controller/UserController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/UserController.java#L313

```text
  310       * @Param: beanJson
  311       * @return java.lang.Object
  312       */
  313      @PostMapping("/addUser")
  314      @ApiOperation(value = "新增用户")
  315      @ResponseBody
  316      public Object addUser(@RequestBody JSONObject obj, HttpServletRequest request)throws Exception{
  317          JSONObject result = ExceptionConstants.standardSuccess();
  318          User userInfo = userService.getCurrentUser();
  319          Tenant tenant = tenantService.getTenantByTenantId(userInfo.getTenantId());
  320          Long count = userService.countUser(null,null);
  321          if(tenant!=null) {
  322              if(count>= tenant.getUserNumLimit()) {
  323                  throw new BusinessParamCheckingException(ExceptionConstants.USER_OVER_LIMIT_FAILED_CODE,
  324                          ExceptionConstants.USER_OVER_LIMIT_FAILED_MSG);
  325              } else {
  326                  UserEx ue= JSONObject.parseObject(obj.toJSONString(), UserEx.class);
  327                  userService.addUserAndOrgUserRel(ue, request);
  328              }
  329          }
  330          return result;
```

2. `jshERP-boot/src/main/java/com/jsh/erp/controller/UserController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/UserController.java#L341

```text
  338       * @Param: beanJson
  339       * @return java.lang.Object
  340       */
  341      @PutMapping("/updateUser")
  342      @ApiOperation(value = "修改用户")
  343      @ResponseBody
  344      public Object updateUser(@RequestBody JSONObject obj, HttpServletRequest request)throws Exception{
  345          JSONObject result = ExceptionConstants.standardSuccess();
  346          UserEx ue= JSONObject.parseObject(obj.toJSONString(), UserEx.class);
  347          userService.updateUserAndOrgUserRel(ue, request);
  348          return result;
  349      }
  350  
```

3. `jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java#L538

```text
  535                      BusinessConstants.LOG_OPERATION_TYPE_ADD,
  536                      ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest());
  537              //检查用户名和登录名
  538              checkLoginName(ue);
  539              //新增用户信息
  540              ue= this.addUser(ue);
  541              if(ue==null){
  542                  logger.error("异常码[{}],异常提示[{}],参数,[{}]",
  543                          ExceptionConstants.USER_ADD_FAILED_CODE,ExceptionConstants.USER_ADD_FAILED_MSG);
  544                  throw new BusinessRunTimeException(ExceptionConstants.USER_ADD_FAILED_CODE,
  545                          ExceptionConstants.USER_ADD_FAILED_MSG);
  546              }
  547              //用户id，根据用户名查询id
  548              Long userId = getIdByLoginName(ue.getLoginName());
  549              if(ue.getRoleId()!=null){
  550                  JSONObject ubObj = new JSONObject();
  551                  ubObj.put("type", "UserRole");
  552                  ubObj.put("keyid", userId);
  553                  ubObj.put("value", "[" + ue.getRoleId() + "]");
  554                  userBusinessService.insertUserBusiness(ubObj, request);
  555              }
  556              if(ue.getOrgaId()!=null && "1".equals(ue.getLeaderFlag())){
  557                  //检查当前机构是否存在经理
  558                  List<User> checkList = userMapperEx.getListByOrgaId(ue.getId(), ue.getOrgaId());
  559                  if(checkList.size()>0) {
  560                      throw new BusinessRunTimeException(ExceptionConstants.USER_LEADER_IS_EXIST_CODE,
  561                              ExceptionConstants.USER_LEADER_IS_EXIST_MSG);
  562                  }
  563              }
  564              //新增用户和机构关联关系
  565              OrgaUserRel oul=new OrgaUserRel();
  566              //机构id
  567              oul.setOrgaId(ue.getOrgaId());
  568              oul.setUserId(userId);
  569              //用户在机构中的排序
  570              oul.setUserBlngOrgaDsplSeq(ue.getUserBlngOrgaDsplSeq());
  571              oul=orgaUserRelService.addOrgaUserRel(oul);
  572              if(oul==null){
  573                  logger.error("异常码[{}],异常提示[{}],参数,[{}]",
  574                          ExceptionConstants.ORGA_USER_REL_ADD_FAILED_CODE,ExceptionConstants.ORGA_USER_REL_ADD_FAILED_MSG);
  575                  throw new BusinessRunTimeException(ExceptionConstants.ORGA_USER_REL_ADD_FAILED_CODE,
  576                          ExceptionConstants.ORGA_USER_REL_ADD_FAILED_MSG);
```

4. `jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java#L684

```text
  681              //检查用户名和登录名
  682              checkLoginName(ue);
  683              //更新用户信息
  684              ue = this.updateUser(ue);
  685              if (ue == null) {
  686                  logger.error("异常码[{}],异常提示[{}],参数,[{}]",
  687                          ExceptionConstants.USER_EDIT_FAILED_CODE, ExceptionConstants.USER_EDIT_FAILED_MSG);
  688                  throw new BusinessRunTimeException(ExceptionConstants.USER_EDIT_FAILED_CODE,
  689                          ExceptionConstants.USER_EDIT_FAILED_MSG);
  690              }
  691              if(ue.getRoleId()!=null){
  692                  JSONObject ubObj = new JSONObject();
  693                  ubObj.put("type", "UserRole");
  694                  ubObj.put("keyid", ue.getId());
  695                  ubObj.put("value", "[" + ue.getRoleId() + "]");
  696                  Long ubId = userBusinessService.checkIsValueExist("UserRole", ue.getId().toString());
  697                  if(ubId!=null) {
  698                      ubObj.put("id", ubId);
  699                      userBusinessService.updateUserBusiness(ubObj, request);
  700                  } else {
  701                      userBusinessService.insertUserBusiness(ubObj, request);
  702                  }
  703              }
  704              if(ue.getOrgaId()!=null && "1".equals(ue.getLeaderFlag())){
  705                  //检查当前机构是否存在经理
  706                  List<User> checkList = userMapperEx.getListByOrgaId(ue.getId(), ue.getOrgaId());
  707                  if(checkList.size()>0) {
  708                      throw new BusinessRunTimeException(ExceptionConstants.USER_LEADER_IS_EXIST_CODE,
  709                              ExceptionConstants.USER_LEADER_IS_EXIST_MSG);
  710                  }
  711              }
  712              //更新用户和机构关联关系
  713              OrgaUserRel oul = new OrgaUserRel();
  714              //机构和用户关联关系id
  715              oul.setId(ue.getOrgaUserRelId());
  716              //机构id
  717              oul.setOrgaId(ue.getOrgaId());
  718              //用户id
  719              oul.setUserId(ue.getId());
  720              //用户在机构中的排序
  721              oul.setUserBlngOrgaDsplSeq(ue.getUserBlngOrgaDsplSeq());
  722              if (oul.getId() != null) {
  723                  //已存在机构和用户的关联关系，更新
  724                  oul = orgaUserRelService.updateOrgaUserRel(oul);
  725              } else {
  726                  //不存在机构和用户的关联关系，新建
  727                  oul = orgaUserRelService.addOrgaUserRel(oul);
  728              }
  729              if (oul == null) {
  730                  logger.error("异常码[{}],异常提示[{}],参数,[{}]",
  731                          ExceptionConstants.ORGA_USER_REL_EDIT_FAILED_CODE, ExceptionConstants.ORGA_USER_REL_EDIT_FAILED_MSG);
  732                  throw new BusinessRunTimeException(ExceptionConstants.ORGA_USER_REL_EDIT_FAILED_CODE,
  733                          ExceptionConstants.ORGA_USER_REL_EDIT_FAILED_MSG);
  734              }
```

5. `jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java#L759

```text
  756      public void checkLoginName(UserEx userEx)throws Exception{
  757          List<User> list=null;
  758          if(userEx==null){
  759              return;
  760          }
  761          Long userId=userEx.getId();
  762          //检查登录名
  763          if(!StringUtils.isEmpty(userEx.getLoginName())){
  764              String loginName=userEx.getLoginName();
  765              list=this.getUserListByloginName(loginName);
  766              if(list!=null&&list.size()>0){
  767                  if(list.size()>1){
  768                      //超过一条数据存在，该登录名已存在
```


## 2. Existing checks and why they fail

- User-count limit only controls capacity.
- Login-name uniqueness is unrelated to authorization.
- `checkRoleAndOrg` validates role/department consistency, not whether the caller may assign that role or organization.
- No target-user management scope or role ceiling exists.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Require user-management permission. Enforce target-user scope, assignable-role ceiling, organization boundary, and prevent users from modifying their own privilege level unless explicitly allowed

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JSH_ERP/issue4.html
