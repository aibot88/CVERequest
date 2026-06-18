---
title: "JEEWMS issue5: `/rest/user` 暴露用户实体 CRUD"
description: "JEEWMS has a missing authorization vulnerability: `/rest/user` 暴露用户实体 CRUD. 可绕过正常用户管理流程，修改账号状态、用户类型、删除用户等授权相关状态；部分字段还可能造成账户控制或业务破坏。"
tags:
  - JEEWMS
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JEEWMS has a missing authorization vulnerability: `/rest/user` 暴露用户实体 CRUD. 可绕过正常用户管理流程，修改账号状态、用户类型、删除用户等授权相关状态；部分字段还可能造成账户控制或业务破坏。

- Attack precondition: 攻击者能访问 `/rest/user` REST API。`AuthInterceptor` 对 `rest/...` 路径直接放行。
- Security impact: 可绕过正常用户管理流程，修改账号状态、用户类型、删除用户等授权相关状态；部分字段还可能造成账户控制或业务破坏。

### 1.2 Exploit path

调用 `/rest/user` 的 POST/PUT/DELETE 创建、修改、删除 `TSUser` 实体。

### 1.3 Key code evidence

1. `src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java#L33

```text
   30   * 
   31   * @author liuht
   32   */
   33  @Controller
   34  @RequestMapping(value = "/user")
   35  public class UserRestController {
   36  
   37  	@Autowired
   38  	private UserService userService;
```

2. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java#L69

```text
   66  	 * 访问地址：http://localhost:8080/jeecg/rest/user/{id}
   67  	 * @param id
   68  	 * @return
   69  	 */
   70  	@RequestMapping(value = "/{id}", method = RequestMethod.GET)
   71  	@ResponseBody
   72  	public ResponseEntity<?> get(@PathVariable("id") String id) {
   73  		TSUser currentUser = currentUser();
   74  		if (currentUser == null) {
   75  			return new ResponseEntity<Object>(HttpStatus.UNAUTHORIZED);
   76  		}
   77  		if (!canReadUsers(currentUser) || !securityHelper().canAccessUser(currentUser, id)) {
   78  			return new ResponseEntity<Object>(HttpStatus.FORBIDDEN);
   79  		}
   80  		TSUser user = userService.get(TSUser.class, id);
   81  		if (user == null) {
   82  			return new ResponseEntity<Object>(HttpStatus.NOT_FOUND);
```

3. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java#L90

```text
   87  	@RequestMapping(method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
   88  	@ResponseBody
   89  	public ResponseEntity<?> create(@RequestBody TSUser user, UriComponentsBuilder uriBuilder) {
   90  		TSUser currentUser = currentUser();
   91  		if (currentUser == null) {
   92  			return new ResponseEntity<Object>(HttpStatus.UNAUTHORIZED);
   93  		}
   94  		if (!canWriteUsers(currentUser)) {
   95  			return new ResponseEntity<Object>(HttpStatus.FORBIDDEN);
   96  		}
   97  		Set<ConstraintViolation<TSUser>> failures = validator.validate(user);
   98  		if (!failures.isEmpty()) {
   99  			return new ResponseEntity<Object>(BeanValidators.extractPropertyAndMessage(failures), HttpStatus.BAD_REQUEST);
  100  		}
  101  		TSUser safeUser = new TSUser();
  102  		copyWritableFields(user, safeUser);
```

4. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java#L105

```text
  102  		copyWritableFields(user, safeUser);
  103  		safeUser.setUserName(user.getUserName());
  104  		if (StringUtil.isNotEmpty(user.getPassword())) {
  105  			safeUser.setPassword(PasswordUtil.encrypt(user.getUserName(), user.getPassword(), PasswordUtil.getStaticSalt()));
  106  		}
  107  		safeUser.setStatus(Globals.User_Normal);
  108  		safeUser.setDeleteFlag(Globals.Delete_Normal);
  109  		userService.save(safeUser);
  110  
  111  		URI uri = uriBuilder.path("/rest/user/" + safeUser.getId()).build().toUri();
```

5. `src/main/java/org/jeecgframework/core/interceptors/AuthInterceptor.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/core/interceptors/AuthInterceptor.java#L95

```text
   92          }
   93          if (excludeUrls.contains(requestPath)) {
   94              return true;
   95          } else if (moHuContain(excludeContainUrls, requestPath)) {
   96              return true;
   97          } else {
   98              // 步骤二： 权限控制，优先重组请求 URL（考虑 online 请求前缀一致问题）
   99              String clickFunctionId = request.getParameter("clickFunctionId");
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

移除或禁用该 REST Controller；至少要求认证和系统管理员权限；对 `TSUser` 使用 DTO 白名单，禁止客户端直接写入账号状态、类型、删除标志等敏感字段。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JEEWMS/issue5.html
