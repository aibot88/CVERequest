---
title: "SpringBlade issue7: `POST /user/grant`"
description: "SpringBlade has a missing authorization vulnerability: `POST /user/grant`. assigned user can receive elevated roles on next login; token creation and route/API checks trust the stored `roleId`"
tags:
  - SpringBlade
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

SpringBlade has a missing authorization vulnerability: `POST /user/grant`. assigned user can receive elevated roles on next login; token creation and route/API checks trust the stored `roleId`

- Attack precondition: tenant admin with `HAS_ROLE_ADMIN`
- Security impact: assigned user can receive elevated roles on next login; token creation and route/API checks trust the stored `roleId`

### 1.2 Exploit path

attacker calls `/user/grant` for a user in their tenant but supplies arbitrary `roleIds`, such as platform administrator or cross-tenant roles

### 1.3 Key code evidence

1. `blade-service/blade-system/src/main/java/org/springblade/system/controller/UserController.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/controller/UserController.java#L161

```text
  158  	 * @param roleIds
  159  	 * @return
  160  	 */
  161  	@PostMapping("/grant")
  162  	@ApiOperationSupport(order = 7)
  163  	@Operation(summary = "权限设置", description = "传入roleId集合以及menuId集合")
  164  	@PreAuth(RoleConstant.HAS_ROLE_ADMIN)
```

2. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java#L208

```text
  205  	@Override
  206  	@Transactional(rollbackFor = Exception.class)
  207  	public boolean registerGuest(User user, Long oauthId) {
  208  		R<Tenant> result = sysClient.getTenant(user.getTenantId());
  209  		Tenant tenant = result.getData();
  210  		if (!result.isSuccess() || tenant == null || tenant.getId() == null) {
  211  			throw new ServiceException("租户信息错误!");
```

3. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java#L212

```text
  209  		Tenant tenant = result.getData();
  210  		if (!result.isSuccess() || tenant == null || tenant.getId() == null) {
  211  			throw new ServiceException("租户信息错误!");
  212  		}
  213  		UserOauth userOauth = userOauthService.getById(oauthId);
  214  		if (userOauth == null || userOauth.getId() == null) {
  215  			throw new ServiceException("第三方登陆信息错误!");
```

4. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java#L165

```text
  162  		if (!user.getPassword().equals(DigestUtil.encrypt(oldPassword))) {
  163  			throw new ServiceException("原密码不正确!");
  164  		}
  165  		return this.update(Wrappers.<User>update().lambda().set(User::getPassword, DigestUtil.encrypt(newPassword)).eq(User::getId, userId));
  166  	}
  167  
  168  	@Override
```

5. `blade-auth/src/main/java/org/springblade/auth/utils/TokenUtil.java`

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

validate every submitted role ID exists, belongs to the current tenant, and is grantable by the current operator. Non-administrator users must not grant `administrator` or equivalent higher roles

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/SpringBlade/issue7.html
