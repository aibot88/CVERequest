---
title: "JSH_ERP issue8: Client-Controlled Tenant Quota and Expiration via `/user/registerUser`"
description: "JSH_ERP has a missing authorization vulnerability in `POST /user/registerUser`. An attacker can self-register a tenant with excessive user quota or an arbitrary future expiration time, bypassing service-side trial and quota controls"
tags:
  - JSH_ERP
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JSH_ERP has a missing authorization vulnerability in `POST /user/registerUser`. An attacker can self-register a tenant with excessive user quota or an arbitrary future expiration time, bypassing service-side trial and quota controls

- Attack precondition: Unauthenticated attacker can complete registration captcha and choose an unused login name
- Affected endpoint: ``POST /user/registerUser``
- Affected authorization property: ``Tenant.userNumLimit`, `Tenant.expireTime``
- Security impact: An attacker can self-register a tenant with excessive user quota or an arbitrary future expiration time, bypassing service-side trial and quota controls

### 1.2 Exploit path

The attacker sends registration JSON containing custom `userNumLimit` and `expireTime`. The service creates the tenant and only applies default values if those fields are null

### 1.3 Key code evidence

1. `jshERP-boot/src/main/java/com/jsh/erp/filter/LogCostFilter.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/filter/LogCostFilter.java#L54

```text
   51          }
   52          if (requestUrl.equals("/jshERP-boot/doc.html") || requestUrl.equals("/jshERP-boot/user/login")
   53                  || requestUrl.equals("/jshERP-boot/user/register") || requestUrl.equals("/jshERP-boot/user/weixinLogin")
   54                  || requestUrl.equals("/jshERP-boot/user/weixinBind") || requestUrl.equals("/jshERP-boot/user/registerUser")
   55                  || requestUrl.equals("/jshERP-boot/user/randomImage")) {
   56              chain.doFilter(request, response);
   57              return;
```

2. `jshERP-boot/src/main/java/com/jsh/erp/controller/UserController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/UserController.java#L357

```text
  354       * @return
  355       * @throws Exception
  356       */
  357      @PostMapping(value = "/registerUser")
  358      @ApiOperation(value = "注册用户")
  359      public Object registerUser(@RequestBody UserEx ue,
  360                                 HttpServletRequest request)throws Exception{
  361          JSONObject result = ExceptionConstants.standardSuccess();
  362          ue.setUsername(ue.getLoginName());
  363          userService.validateCaptcha(ue.getCode(), ue.getUuid());
  364          userService.checkLoginName(ue); //检查登录名
  365          userService.registerUser(ue,manageRoleId,request);
  366          return result;
  367      }
  368  
```

3. `jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java#L643

```text
  640              userBusinessService.insertUserBusiness(ubObj, null);
  641              //创建租户信息
  642              JSONObject tenantObj = new JSONObject();
  643              tenantObj.put("tenantId", ue.getId());
  644              tenantObj.put("loginName",ue.getLoginName());
  645              tenantObj.put("userNumLimit", ue.getUserNumLimit());
  646              tenantObj.put("expireTime", ue.getExpireTime());
  647              tenantObj.put("remark", ue.getRemark());
  648              Tenant tenant = JSONObject.parseObject(tenantObj.toJSONString(), Tenant.class);
  649              tenant.setCreateTime(new Date());
  650              if(tenant.getUserNumLimit()==null) {
  651                  tenant.setUserNumLimit(userNumLimit); //默认用户限制数量
  652              }
  653              if(tenant.getExpireTime()==null) {
```

4. `jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java#L652

```text
  649              tenant.setCreateTime(new Date());
  650              if(tenant.getUserNumLimit()==null) {
  651                  tenant.setUserNumLimit(userNumLimit); //默认用户限制数量
  652              }
  653              if(tenant.getExpireTime()==null) {
  654                  tenant.setExpireTime(Tools.addDays(new Date(), tryDayLimit)); //租户允许试用的天数
  655              }
  656              tenantMapper.insertSelective(tenant);
  657              logger.info("===============创建租户信息完成===============");
  658          }
  659      }
  660  
```

5. `jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserService.java#L658

```text
  655              }
  656              tenantMapper.insertSelective(tenant);
  657              logger.info("===============创建租户信息完成===============");
  658          }
  659      }
  660  
  661      @Transactional(value = "transactionManager", rollbackFor = Exception.class)
```


## 2. Existing checks and why they fail

- Captcha prevents simple automated abuse, but does not authorize quota or expiration values.
- Login-name uniqueness is unrelated to tenant entitlement.
- `tenantId` and default role are server-derived, but quota and expiration are client-controlled.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Ignore client-supplied quota and expiration during public registration. Always use server-side configured defaults. Allow quota and expiration changes only through an authenticated administrative billing/tenant-management path

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JSH_ERP/issue8.html
