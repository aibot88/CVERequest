---
title: "JSH_ERP issue1: Arbitrary Password Reset via `/user/resetPwd`"
description: "JSH_ERP has a missing authorization vulnerability in `POST /user/resetPwd`. A low-privileged user can reset and take over any non-`admin` account in the same reachable data scope. If the target account has higher business privileges, this becomes privilege escalation and account takeover"
tags:
  - JSH_ERP
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JSH_ERP has a missing authorization vulnerability in `POST /user/resetPwd`. A low-privileged user can reset and take over any non-`admin` account in the same reachable data scope. If the target account has higher business privileges, this becomes privilege escalation and account takeover

- Attack precondition: Any authenticated user. The target account must not have login name `admin`
- Affected endpoint: ``POST /user/resetPwd``
- Affected authorization property: `user account password and account control state`
- Security impact: A low-privileged user can reset and take over any non-`admin` account in the same reachable data scope. If the target account has higher business privileges, this becomes privilege escalation and account takeover

### 1.2 Exploit path

An authenticated attacker sends a request body containing another user's `id` and a new `password`. The controller passes both values directly into `userService.resetPwd`. The service only checks whether the target login name is `admin`; otherwise it updates the target user's password

### 1.3 Key code evidence

1. `jshERP-boot/src/main/java/com/jsh/erp/controller/UserController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/UserController.java#L230

```text
  227          return res;
  228      }
  229
  230      @PostMapping(value = "/resetPwd")
  231      @ApiOperation(value = "[non-English text removed]")
  232      public String resetPwd(@RequestBody JSONObject jsonObject,
  233                                       HttpServletRequest request) throws Exception {
```

2. `jshERP-boot/src/main/java/com/jsh/erp/controller/UserController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/UserController.java#L234

```text
  231      @ApiOperation(value = "[non-English text removed]")
  232      public String resetPwd(@RequestBody JSONObject jsonObject,
  233                                       HttpServletRequest request) throws Exception {
  234          Map<String, Object> objectMap = new HashMap<>();
  235          Long id = jsonObject.getLong("id");
  236          String md5Pwd = jsonObject.getString("password");
  237          int update = userService.resetPwd(md5Pwd, id, request);
  238          if(update > 0) {
  239              return returnJson(objectMap, SUCCESS, ErpInfo.OK.code);
  240          } else {
```

3. `jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java#L213

```text
  210      }
  211
  212      @Transactional(value = "transactionManager", rollbackFor = Exception.class)
  213      public int resetPwd(String md5Pwd, Long id, HttpServletRequest request) throws Exception{
  214          int result=0;
  215          User u = getUser(id);
  216          String loginName = u.getLoginName();
  217          if("admin".equals(loginName)){
  218              logger.info("[non-English text removed]");
  219          } else {
  220              User user = new User();
  221              user.setId(id);
  222              user.setPassword(md5Pwd);
  223              try{
  224                  //[non-English text removed]
  225                  Object userId = redisService.getObjectFromSessionByKey(request,"userId");
  226                  if (userId != null) {
  227                      result = userMapper.updateByPrimaryKeySelective(user);
  228                      logService.insertLog("[non-English text removed]",
  229                              new StringBuffer(BusinessConstants.LOG_OPERATION_TYPE_EDIT).append(id).toString(),
  230                              ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest());
  231                  }
  232              }catch(Exception e){
  233                  JshException.writeFail(logger, e);
  234              }
  235          }
  236          return result;
  237      }
  238
```

4. `jshERP-boot/src/main/java/com/jsh/erp/filter/LogCostFilter.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/filter/LogCostFilter.java#L48

```text
   45          }
   46          //[non-English text removed],[non-English text removed]:[non-English text removed],[non-English text removed]
   47          Object userId = redisService.getObjectFromSessionByKey(servletRequest,"userId");
   48          if(userId!=null) { //[non-English text removed],[non-English text removed]
   49              chain.doFilter(request, response);
   50              return;
   51          }
```


## 2. Existing checks and why they fail

- Login check: only proves the caller is authenticated, not authorized to reset another user's password. - `admin` exclusion: protects only the literal super-admin login name and does not protect tenant admins or other privileged users. - No old-password check is required for the target account. - No user-management permission or target-user scope check exists

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Separate self-service password change from administrative reset. For self-service, require current password verification. For administrative reset, require explicit user-management permission, target tenant/org scope validation, and protection against resetting equal or higher-privileged accounts

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JSH_ERP/issue1.html
