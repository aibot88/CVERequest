---
title: "lamp-cloud issue6: Unauthorized Permission Disclosure via `GET /anyone/visible/resource`"
description: "lamp-cloud has a missing authorization vulnerability in `GET /anyone/visible/resource`. Disclosure of another employee's authorization profile, including role list, resource code list, and router/menu list"
tags:
  - lamp-cloud
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lamp-cloud has a missing authorization vulnerability in `GET /anyone/visible/resource`. Disclosure of another employee's authorization profile, including role list, resource code list, and router/menu list

- Attack precondition: Any logged-in user who knows or can guess a target `employeeId`
- Affected endpoint: ``GET /anyone/visible/resource``
- Affected authorization property: `employee role codes, employee resource codes, visible router/resource list`
- Security impact: Disclosure of another employee's authorization profile, including role list, resource code list, and router/menu list

### 1.2 Exploit path

Call the endpoint with a positive target `employeeId`. The endpoint uses the supplied employee ID instead of forcing the current employee

### 1.3 Key code evidence

1. `lamp-oauth/lamp-oauth-controller/src/main/java/top/tangyh/lamp/oauth/controller/ResourceController.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-oauth/lamp-oauth-controller/src/main/java/top/tangyh/lamp/oauth/controller/ResourceController.java
2. `lamp-support/lamp-boot-server/src/main/resources/application.yml`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-support/lamp-boot-server/src/main/resources/application.yml#L73

```text
   70      caseSensitive: false
   71      # 系统没有配置某个URI时，是否允许访问
   72      notConfigUriAllow: false
   73      anyone: # 请求中 需要携带Tenant 且 需要携带Token(不需要登录)，但不需要验证uri权限
   74        ALL:
   75          - /anyone/**
   76          - /service/model/*/json
   77          - /service/model/*/save
   78          - /service/editor/stencilset
```

3. `lamp-support/lamp-boot-server/src/main/java/top/tangyh/lamp/base/interceptor/AuthenticationSaInterceptor.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-support/lamp-boot-server/src/main/java/top/tangyh/lamp/base/interceptor/AuthenticationSaInterceptor.java#L73

```text
   70                      })
   71                      .check(r -> StpUtil.checkLogin());
   72  
   73              // 接口权限
   74              Map<String, Set<String>> anyone = ignoreProperties.buildAnyone();
   75              Map<String, Set<String>> allApi = this.defResourceFacade.listAllApi();
   76  
   77              allApi.forEach((api, auth) -> {
   78                  List<String> list = StrUtil.split(api, "###");
   79                  String uri = list.get(0);
   80                  String requestMethod = list.get(1);
   81                  SaRouter.match(uri).matchMethod(requestMethod)
   82                          .notMatch(r -> {
   83                              String path = SaHolder.getRequest().getRequestPath();
   84                              String method = SaHolder.getRequest().getMethod();
   85                              for (Map.Entry<String, Set<String>> map : anyone.entrySet()) {
   86                                  String key = map.getKey();
   87                                  Set<String> value = map.getValue();
   88                                  if (StrUtil.equalsAny(key, method, SaHttpMethod.ALL.name())) {
   89                                      for (String ignore : value) {
   90                                          if (StrUtil.equals(ignore, path)) {
   91                                              return true;
   92                                          }
   93  
   94                                          if (SaPathPatternParserUtil.match(ignore, path)) {
   95                                              return true;
   96                                          }
   97                                      }
   98                                  }
   99                              }
  100                              return false;
  101                          })
  102                          .check(r -> StpUtil.checkPermissionOr(auth.toArray(String[]::new)));
  103              });
  104  
  105  
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Ignore request-supplied `employeeId` for this self-service endpoint, or require explicit administrative permission and object-scope authorization for reading other employees

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lamp-cloud/issue6.html
