---
title: "lamp-cloud issue5: Unauthorized Password Reset via `PUT /defUser/resetPassword`"
description: "lamp-cloud has a missing authorization vulnerability in `PUT /defUser/resetPassword`. Account takeover, including possible takeover of high-privilege accounts"
tags:
  - lamp-cloud
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lamp-cloud has a missing authorization vulnerability in `PUT /defUser/resetPassword`. Account takeover, including possible takeover of high-privilege accounts

- Attack precondition: The attacker is logged in and has the URI/API permission for this endpoint, but should not be allowed to reset arbitrary users' passwords
- Affected endpoint: ``PUT /defUser/resetPassword``
- Affected authorization property: ``def_user.password`, `def_user.salt`, password error state fields`
- Security impact: Account takeover, including possible takeover of high-privilege accounts

### 1.2 Exploit path

Submit a target user `id` and a new password, or request use of the system default password

### 1.3 Key code evidence

1. `lamp-system/lamp-system-controller/src/main/java/top/tangyh/lamp/system/controller/tenant/DefUserController.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-system/lamp-system-controller/src/main/java/top/tangyh/lamp/system/controller/tenant/DefUserController.java
2. `lamp-system/lamp-system-biz/src/main/java/top/tangyh/lamp/system/service/tenant/impl/DefUserServiceImpl.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-system/lamp-system-biz/src/main/java/top/tangyh/lamp/system/service/tenant/impl/DefUserServiceImpl.java#L190

```text
  187          } else {
  188              ArgumentAssert.notEmpty(data.getConfirmPassword(), "请输入确认密码");
  189              ArgumentAssert.notEmpty(data.getPassword(), "请输入密码");
  190              ArgumentAssert.equals(data.getConfirmPassword(), data.getPassword(), "密码和确认密码不一致");
  191          }
  192          DefUser user = superManager.getById(data.getId());
  193          ArgumentAssert.notNull(user, "您要重置密码的用户不存在");
  194  
  195          return updateUserPassword(user.getId(), data.getPassword(), user.getSalt());
  196      }
  197  
  198      @Override
  199      @Transactional(rollbackFor = Exception.class)
  200      public Boolean updateState(Long id, Boolean state) {
  201          // 演示环境专用标识，用于WriteInterceptor拦截器判断演示环境需要禁止用户执行sql，若您无需搭建演示环境，可以删除下面一行代码
  202          ContextUtil.setStop();
  203          return superManager.updateById(DefUser.builder().state(state).id(id).build());
  204      }
```

3. `lamp-system/lamp-system-entity/src/main/java/top/tangyh/lamp/system/vo/update/tenant/DefUserPasswordResetVO.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-system/lamp-system-entity/src/main/java/top/tangyh/lamp/system/vo/update/tenant/DefUserPasswordResetVO.java#L39

```text
   36  
   37      private static final long serialVersionUID = 1L;
   38  
   39      @Schema(description = "主键")
   40      @NotNull(message = "id不能为空")
   41      private Long id;
   42  
   43      @Schema(description = "是否使用系统内置密码")
   44      @NotNull(message = "请选择是否使用系统内置密码")
   45      private Boolean isUseSystemPassword;
   46      /**
   47       * 密码
   48       */
   49      @Schema(description = "密码")
   50      @Size(min = 6, max = 20, message = "密码长度不能小于{min}且超过{max}个字符")
   51      @NotEmptyPattern(regexp = REGEX_PASSWORD, message = "至少包含字母、数字、特殊字符")
   52      private String password;
   53  
   54      /**
   55       * 密码
   56       */
   57      @Schema(description = "确认密码")
   58      @Size(min = 6, max = 20, message = "密码长度不能小于{min}且超过{max}个字符")
   59      private String confirmPassword;
   60  
   61  }
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Allow only self-reset with proper old-password or MFA validation, or authorized administrators within management scope. Deny resetting equal/higher privilege accounts unless explicitly permitted

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lamp-cloud/issue5.html
