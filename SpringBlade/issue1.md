---
title: "SpringBlade issue1: `POST /user/save-user`"
description: "SpringBlade has a missing authorization vulnerability: `POST /user/save-user`. creates a user with attacker-controlled authorization bindings. Later login/token generation trusts `tenantId`, `roleId`, and `deptId` from the database"
tags:
  - SpringBlade
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

SpringBlade has a missing authorization vulnerability: `POST /user/save-user`. creates a user with attacker-controlled authorization bindings. Later login/token generation trusts `tenantId`, `roleId`, and `deptId` from the database

- Attack precondition: low-privileged authenticated user can reach `/user/save-user`
- Security impact: creates a user with attacker-controlled authorization bindings. Later login/token generation trusts `tenantId`, `roleId`, and `deptId` from the database

### 1.2 Exploit path

attacker submits a new `User` object with chosen `tenantId`, privileged `roleId`, and chosen department/post bindings. `UserClient.saveUser` directly calls `service.save(user)`

### 1.3 Key code evidence

1. `blade-service-api/blade-user-api/src/main/java/org/springblade/system/user/feign/IUserClient.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service-api/blade-user-api/src/main/java/org/springblade/system/user/feign/IUserClient.java#L78

```text
   75  	 * @param user 用户实体
   76  	 * @return
   77  	 */
   78  	@PostMapping(API_PREFIX + "/save-user")
   79  	R<Boolean> saveUser(@RequestBody User user);
   80  
   81  }
```

2. `blade-service/blade-system/src/main/java/org/springblade/system/feign/UserClient.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/feign/UserClient.java#L60

```text
   57  	}
   58  
   59  	@Override
   60  	@PostMapping(API_PREFIX + "/save-user")
   61  	public R<Boolean> saveUser(User user) {
   62  		return R.data(service.save(user));
   63  	}
```

3. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java#L73

```text
   70  
   71  	@Override
   72  	public boolean updateUserInfo(User user) {
   73  		// 用户修改自身信息强制指定当前请求账号的ID
   74  		user.setId(SecureUtil.getUserId());
   75  		User currentUser = getById(user.getId());
   76  		if (currentUser == null) {
```

4. `blade-auth/src/main/java/org/springblade/auth/utils/TokenUtil.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-auth/src/main/java/org/springblade/auth/utils/TokenUtil.java#L51

```text
   48  	public final static String HEADER_KEY = "Authorization";
   49  	public final static String HEADER_PREFIX = "Basic ";
   50  	public final static String ENCRYPT_PREFIX = "04";
   51  	public final static String USER_HAS_TOO_MANY_FAILS = "用户登录失败次数过多";
   52  	public final static String IP_HAS_TOO_MANY_FAILS = "用户登录失败次数过多，请稍后再试";
   53  	public final static String DEFAULT_AVATAR = "https://bladex.cn/images/logo.png";
   54  
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

do not expose this Feign route externally; require internal-call authentication. Route user creation through `userService.submit`, whitelist accepted fields, bind tenant server-side, and validate role/dept/post IDs against current tenant and current operator grant scope

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/SpringBlade/issue1.html
