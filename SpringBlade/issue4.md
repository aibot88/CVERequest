---
title: "SpringBlade issue4: `GET /user/detail` and `GET /user/user-list`"
description: "SpringBlade has a missing authorization vulnerability: `GET /user/detail` and `GET /user/user-list`. cross-tenant exposure of user authorization bindings and organizational relationships"
tags:
  - SpringBlade
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

SpringBlade has a missing authorization vulnerability: `GET /user/detail` and `GET /user/user-list`. cross-tenant exposure of user authorization bindings and organizational relationships

- Attack precondition: tenant admin with `HAS_ROLE_ADMIN`
- Security impact: cross-tenant exposure of user authorization bindings and organizational relationships

### 1.2 Exploit path

attacker calls `/user/detail` with another tenant's user ID or `/user/user-list` with broad conditions. Controller directly queries using user-controlled conditions without tenant scoping

### 1.3 Key code evidence

1. `blade-service/blade-system/src/main/java/org/springblade/system/controller/UserController.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/controller/UserController.java#L80

```text
   77  	private IUserService userService;
   78  	private BladeRedis bladeRedis;
   79  
   80  	/**
   81  	 * 查询单条
   82  	 */
   83  	@ApiOperationSupport(order = 1)
```

2. `blade-service/blade-system/src/main/java/org/springblade/system/controller/UserController.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/controller/UserController.java#L199

```text
  196  	}
  197  
  198  	/**
  199  	 * 用户列表
  200  	 *
  201  	 * @param user
  202  	 * @return
```

3. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java#L151

```text
  148  	@Override
  149  	public boolean resetPassword(String userIds) {
  150  		User user = new User();
  151  		user.setPassword(DigestUtil.encrypt(CommonConstant.DEFAULT_PASSWORD));
  152  		user.setUpdateTime(DateUtil.now());
  153  		return this.update(user, Wrappers.<User>update().lambda().in(User::getId, Func.toLongList(userIds)));
  154  	}
```

4. `blade-service/blade-system/src/main/java/org/springblade/system/wrapper/UserWrapper.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/wrapper/UserWrapper.java#L43

```text
   40  
   41  	static {
   42  		userService = SpringUtil.getBean(IUserService.class);
   43  		dictClient = SpringUtil.getBean(IDictClient.class);
   44  	}
   45  
   46  	public static UserWrapper build() {
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

route detail/list through service methods that enforce tenant scope. For non-administrator users, append `tenant_id = SecureUtil.getTenantId()` regardless of request parameters

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/SpringBlade/issue4.html
