---
title: "JSH_ERP issue2: Unauthorized Read of Authorization Relationships via `/userBusiness/getBasicData`"
description: "JSH_ERP has a missing authorization vulnerability in `GET /userBusiness/getBasicData`. The endpoint discloses authorization relationships: users' roles, role functions/buttons, warehouse access, and customer access. These relationships are consumed by permission and data-scope logic throughout the application"
tags:
  - JSH_ERP
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JSH_ERP has a missing authorization vulnerability in `GET /userBusiness/getBasicData`. The endpoint discloses authorization relationships: users' roles, role functions/buttons, warehouse access, and customer access. These relationships are consumed by permission and data-scope logic throughout the application

- Attack precondition: Any authenticated user who knows or can guess `KeyId` and `Type`
- Affected endpoint: ``GET /userBusiness/getBasicData``
- Affected authorization property: ``UserBusiness.type`, `UserBusiness.keyId`, `UserBusiness.value`, `UserBusiness.btnStr``
- Security impact: The endpoint discloses authorization relationships: users' roles, role functions/buttons, warehouse access, and customer access. These relationships are consumed by permission and data-scope logic throughout the application

### 1.2 Exploit path

The attacker calls `/userBusiness/getBasicData?KeyId=<target>&Type=<relationship-type>`, for example `UserRole`, `RoleFunctions`, `UserDepot`, or `UserCustomer`. The endpoint returns matching `jsh_user_business` rows including role, menu/button, warehouse, or customer relationship values

### 1.3 Key code evidence

1. `jshERP-boot/src/main/java/com/jsh/erp/controller/UserBusinessController.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/controller/UserBusinessController.java#L104

```text
  101       * @return
  102       * @throws Exception
  103       */
  104      @GetMapping(value = "/getBasicData")
  105      @ApiOperation(value = "获取信息")
  106      public BaseResponseInfo getBasicData(@RequestParam(value = "KeyId") String keyId,
  107                                           @RequestParam(value = "Type") String type,
  108                                           HttpServletRequest request)throws Exception {
  109          BaseResponseInfo res = new BaseResponseInfo();
  110          try {
  111              List<UserBusiness> list = userBusinessService.getBasicData(keyId, type);
  112              Map<String, List> mapData = new HashMap<String, List>();
  113              mapData.put("userBusinessList", list);
  114              res.code = 200;
  115              res.data = mapData;
  116          } catch (Exception e) {
  117              logger.error(e.getMessage(), e);
  118              res.code = 500;
```

2. `jshERP-boot/src/main/java/com/jsh/erp/service/UserBusinessService.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/service/UserBusinessService.java#L125

```text
  122          return 1;
  123      }
  124  
  125      public List<UserBusiness> getBasicData(String keyId, String type)throws Exception{
  126          List<UserBusiness> list=null;
  127          try{
  128              list= userBusinessMapperEx.getBasicDataByKeyIdAndType(keyId, type);
  129          }catch(Exception e){
  130              JshException.readFail(logger, e);
  131          }
```

3. `jshERP-boot/src/main/resources/mapper_xml/UserBusinessMapperEx.xml`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/resources/mapper_xml/UserBusinessMapperEx.xml#L15

```text
   12          )
   13      </update>
   14  
   15      <select id="getBasicDataByKeyIdAndType" resultType="com.jsh.erp.datasource.entities.UserBusiness">
   16          select * from jsh_user_business
   17          where key_id=#{keyId} and type=#{type}
   18          and ifnull(delete_flag,'0') !='1'
   19      </select>
   20  
   21      <update id="updateValueByTypeAndKeyId">
   22          update jsh_user_business
```

4. `jshERP-boot/src/main/java/com/jsh/erp/config/TenantConfig.java`

Evidence location: https://gitee.com/jishenghua/JSH_ERP/blob/master/jshERP-boot/src/main/java/com/jsh/erp/config/TenantConfig.java#L88

```text
   85                  } else if ("com.jsh.erp.datasource.mappers.LogMapperEx.insertLogWithUserId".equals(ms.getId())) {
   86                      return true;
   87                  } else if ("com.jsh.erp.datasource.mappers.UserBusinessMapperEx.getBasicDataByKeyIdAndType".equals(ms.getId())) {
   88                      return true;
   89                  }
   90                  return false;
   91              }
```


## 2. Existing checks and why they fail

- The login filter only checks session existence.
- No check ensures the caller is reading their own relationship or an object they administer.
- The custom mapper is excluded from tenant filtering, so tenant scoping is not a reliable fallback here.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Remove this generic relationship-read endpoint from ordinary users. Expose scoped, purpose-specific endpoints that derive the target from the current session or enforce explicit management permission and target scope

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JSH_ERP/issue2.html
