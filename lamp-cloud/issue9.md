---
title: "lamp-cloud issue9: Unauthorized Current Organization Context Switch via `PUT /anyone/switchTenantAndOrg`"
description: "lamp-cloud has a missing authorization vulnerability in `PUT /anyone/switchTenantAndOrg`. The attacker can forge their current company/department context. Downstream data-scope logic may use this context for access decisions"
tags:
  - lamp-cloud
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lamp-cloud has a missing authorization vulnerability in `PUT /anyone/switchTenantAndOrg`. The attacker can forge their current company/department context. Downstream data-scope logic may use this context for access decisions

- Attack precondition: Any logged-in user with an employee record; target `orgId` exists
- Affected endpoint: ``PUT /anyone/switchTenantAndOrg``
- Affected authorization property: ``base_employee.last_company_id`, `base_employee.last_dept_id`, token/session current organization context`
- Security impact: The attacker can forge their current company/department context. Downstream data-scope logic may use this context for access decisions

### 1.2 Exploit path

Submit an existing organization ID that the current employee does not belong to

### 1.3 Key code evidence

1. `lamp-oauth/lamp-oauth-controller/src/main/java/top/tangyh/lamp/oauth/controller/RootController.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-oauth/lamp-oauth-controller/src/main/java/top/tangyh/lamp/oauth/controller/RootController.java
2. `lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/granter/AbstractTokenGranter.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/granter/AbstractTokenGranter.java#L440

```text
  437      }
  438  
  439      @Override
  440      public LoginResultVO switchOrg(Long orgId) {
  441          StpUtil.checkLogin();
  442          Long userId = ContextUtil.getUserId();
  443          DefUser defUser = defUserService.getByIdCache(userId);
  444          if (defUser == null) {
  445              throw UnauthorizedException.wrap(ExceptionCode.JWT_TOKEN_EXPIRED);
  446          }
  447  
  448          if (!Convert.toBool(defUser.getState(), true)) {
  449              throw UnauthorizedException.wrap(ExceptionCode.JWT_USER_DISABLE);
  450          }
  451  
  452          BaseEmployee employee = baseEmployeeService.getEmployeeByUser(userId);
  453          ArgumentAssert.notNull(employee, "您不属于该公司，无法切换");
  454          if (!Convert.toBool(employee.getState(), true)) {
  455              throw BizException.wrap(ExceptionCode.JWT_EMPLOYEE_DISABLE);
  456          }
  457  
  458          Long topCompanyId = null;
  459          Long companyId = null;
  460          Long deptId = null;
  461          if (orgId != null) {
  462              BaseOrg selectOrg = baseOrgService.getByIdCache(orgId);
  463              ArgumentAssert.notNull(selectOrg, "该部门不存在");
  464  
  465              if (OrgTypeEnum.COMPANY.eq(selectOrg.getType())) {
  466                  companyId = selectOrg.getId();
  467  
  468                  Long rootId = TreeUtil.getTopNodeId(selectOrg.getTreePath());
  469                  if (rootId != null) {
  470                      BaseOrg rootCompany = baseOrgService.getByIdCache(rootId);
  471                      topCompanyId = rootCompany != null ? rootCompany.getId() : companyId;
  472                  } else {
  473                      topCompanyId = companyId;
  474                  }
  475              } else {
  476                  deptId = selectOrg.getId();
  477  
  478                  BaseOrg company = baseOrgService.getCompanyByDeptId(deptId);
  479                  if (company != null) {
  480                      companyId = company.getId();
  481  
  482                      Long rootId = TreeUtil.getTopNodeId(company.getTreePath());
  483                      if (rootId != null) {
  484                          BaseOrg rootCompany = baseOrgService.getByIdCache(rootId);
  485                          topCompanyId = rootCompany != null ? rootCompany.getId() : companyId;
  486                      } else {
  487                          topCompanyId = companyId;
  488                      }
  489                  }
  490              }
  491  
  492              baseEmployeeService.updateOrgInfo(employee.getId(), companyId, deptId);
  493          } else {
  494              baseEmployeeService.updateOrgInfo(employee.getId(), companyId, deptId);
  495          }
  496  
  497  
  498          Employee e = Employee.builder()
  499                  .employeeId(employee.getId())
  500                  .build();
  501  
  502          Org org = Org.builder()
  503                  .currentTopCompanyId(topCompanyId)
  504                  .currentCompanyId(companyId)
  505                  .currentDeptId(deptId)
  506                  .build();
  507  
  508          LoginResultVO loginResultVO = buildResult(e, org, defUser);
  509  
  510          LoginStatusDTO loginStatus = LoginStatusDTO.switchOrg(defUser.getId(), employee.getId());
  511          SpringUtils.publishEvent(new LoginEvent(loginStatus));
```

3. `lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/user/impl/BaseEmployeeServiceImpl.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/user/impl/BaseEmployeeServiceImpl.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Before updating `lastCompanyId` or `lastDeptId`, verify that the target organization is in the current employee's allowed organization set from `base_employee_org_rel`

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lamp-cloud/issue9.html
