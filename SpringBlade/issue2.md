---
title: "SpringBlade issue2: `POST /user/user-auth-info`"
description: "SpringBlade has a missing authorization vulnerability in POST /user/user-auth-info, /user/user-auth-info, uuid/source, tenantId/uuid/source. OAuth account binding hijack; attacker-controlled social identity can become bound to another local user and obtain that user's login context/token"
tags:
  - SpringBlade
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

SpringBlade has a missing authorization vulnerability in POST /user/user-auth-info, /user/user-auth-info, uuid/source, tenantId/uuid/source. OAuth account binding hijack; attacker-controlled social identity can become bound to another local user and obtain that user's login context/token

- Attack precondition: authenticated attacker can reach `/user/user-auth-info` and can control a social `uuid/source` pair
- Affected endpoint: `POST /user/user-auth-info, /user/user-auth-info, uuid/source, tenantId/uuid/source`
- Affected authorization property: `@RestController, userOauth.userId, userOauth.tenantId, userOauth.uuid, userOauth.source, UserOauth`
- Security impact: OAuth account binding hijack; attacker-controlled social identity can become bound to another local user and obtain that user's login context/token

### 1.2 Exploit path

attacker posts `UserOauth` with attacker-controlled `uuid/source` and `userId` set to a target local user. If no record exists, the service saves it. Later social login with the same `uuid/source` hits the saved row and loads `uo.userId` as the authenticated user

### 1.3 Key code evidence

1. `blade-service-api/blade-user-api/src/main/java/org/springblade/system/user/feign/IUserClient.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service-api/blade-user-api/src/main/java/org/springblade/system/user/feign/IUserClient.java#L69

```text
   66  	 * @param userOauth [non-English text removed]
   67  	 * @return UserInfo
   68  	 */
   69  	@PostMapping(API_PREFIX + "/user-auth-info")
   70  	R<UserInfo> userAuthInfo(@RequestBody UserOauth userOauth);
   71
   72  	/**
```

2. `blade-service/blade-system/src/main/java/org/springblade/system/feign/UserClient.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/feign/UserClient.java#L54

```text
   51  	}
   52
   53  	@Override
   54  	@PostMapping(API_PREFIX + "/user-auth-info")
   55  	public R<UserInfo> userAuthInfo(UserOauth userOauth) {
   56  		return R.data(service.userInfo(userOauth));
   57  	}
```

3. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java#L183

```text
  180  		data.forEach(userExcel -> {
  181  			User user = Objects.requireNonNull(BeanUtil.copyProperties(userExcel, User.class));
  182  			// [non-English text removed]ID
  183  			user.setDeptId(sysClient.getDeptIds(userExcel.getTenantId(), userExcel.getDeptName()));
  184  			// [non-English text removed]ID
  185  			user.setPostId(sysClient.getPostIds(userExcel.getTenantId(), userExcel.getPostName()));
  186  			// [non-English text removed]ID
```

4. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java#L190

```text
  187  			user.setRoleId(sysClient.getRoleIds(userExcel.getTenantId(), userExcel.getRoleName()));
  188  			// [non-English text removed]
  189  			user.setPassword(CommonConstant.DEFAULT_PASSWORD);
  190  			this.submit(user);
  191  		});
  192  	}
  193
```

5. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/UserServiceImpl.java#L194

```text
  191  		});
  192  	}
  193
  194  	@Override
  195  	public List<UserExcel> exportUser(Wrapper<User> queryWrapper) {
  196  		List<UserExcel> userList = baseMapper.exportUser(queryWrapper);
  197  		userList.forEach(user -> {
```

6. `blade-auth/src/main/java/org/springblade/auth/granter/SocialTokenGranter.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-auth/src/main/java/org/springblade/auth/granter/SocialTokenGranter.java#L81

```text
   78  			throw new ServiceException("social grant failure, auth response is not success");
   79  		}
   80
   81  		// [non-English text removed]
   82  		UserOauth userOauth = Objects.requireNonNull(BeanUtil.copyProperties(authUser, UserOauth.class));
   83  		userOauth.setSource(authUser.getSource());
   84  		userOauth.setTenantId(tenantId);
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

make the endpoint internal-only; ignore or clear client-supplied `id`, `userId`, and `tenantId`; bind `tenantId/uuid/source` only from verified OAuth context; require explicit, user-confirmed account linking before setting `userId`

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/SpringBlade/issue2.html
