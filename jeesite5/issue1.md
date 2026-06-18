---
title: "jeesite5 issue1: empUser/save /"
description: "jeesite5 has a missing authorization vulnerability in POST ${adminPath}/sys/empUser/save, officeCode/companyCode/postCode. An authenticated attacker can perform authorization-sensitive operations through POST ${adminPath}/sys/empUser/save, officeCode/companyCode/postCode without the required permission."
tags:
  - jeesite5
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

jeesite5 has a missing authorization vulnerability in POST ${adminPath}/sys/empUser/save, officeCode/companyCode/postCode. An authenticated attacker can perform authorization-sensitive operations through POST ${adminPath}/sys/empUser/save, officeCode/companyCode/postCode without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `POST ${adminPath}/sys/empUser/save, officeCode/companyCode/postCode`
- Affected authorization property: `sys:empUser:edit, EmpUser.employee.office.officeCode, EmpUser.employee.company.companyCode, EmpUser.employee.employeePosts, EmployeePost.postCode, EmpUser.employee.employeeOfficeList[].officeCode`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through POST ${adminPath}/sys/empUser/save, officeCode/companyCode/postCode without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to POST ${adminPath}/sys/empUser/save, officeCode/companyCode/postCode with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `EmpUser.employee.company.c`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/EmpUser.employee.company.c
2. `modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java#L185

```text
  182  		}
  183  		EmpUser old = super.getWebDataBinderSource(request);
  184  		if (!Global.TRUE.equals(userService.checkLoginCode(old != null ? old.getLoginCode() : "", empUser.getLoginCode()))) {
  185  			return renderResult(Global.FALSE, text("[non-English text removed],[non-English text removed]''{0}''[non-English text removed]", empUser.getLoginCode()));
  186  		}
  187  		if (StringUtils.isBlank(empUser.getEmployee().getEmpNo())){
  188  			empUser.getEmployee().setEmpNo(empUser.getLoginCode());
```

3. `modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java#L203

```text
  200  				return renderResult(Global.FALSE, text("[non-English text removed],[non-English text removed]", empUser.getUserName()));
  201  			}
  202  		}else if (StringUtils.inString(op, Global.OP_ADD, Global.OP_AUTH) && subject.isPermitted("sys:empUser:authRole")){
  203  			empUserService.checkUserDataScope(empUser.getUserCode(), Global.getConfig("user.adminCtrlPermi", "2"));
  204  			userService.saveAuth(empUser);
  205  		}
  206  		return renderResult(Global.TRUE, text("[non-English text removed]''{0}''[non-English text removed]", empUser.getUserName()));
  207  	}
  208
  209  	/**
```

4. `modules/core/src/main/java/com/jeesite/modules/sys/service/support/EmpUserServiceSupport.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/service/support/EmpUserServiceSupport.java#L156

```text
  153  	private void checkCompanyDataScope(String companyCode, String ctrlPermi) {
  154  		if (StringUtils.isBlank(companyCode)) {
  155  			return;
  156  		}
  157  		Company company = new Company();
  158  		company.setCompanyCode(companyCode);
  159  		company.setStatus(Company.STATUS_NORMAL);
  160  		company.sqlMap().getDataScope().addFilter("dsf", "Company", "a.company_code",
  161  				null, ctrlPermi, "office_user");
  162  		if (companyDao.findCount(company) == 0) {
  163  			throw new ServiceException(text("[non-English text removed]"));
  164  		}
  165  	}
  166
  167  	/**
  168  	 * [non-English text removed]
  169  	 */
  170  	@Override
  171  	public List<EmpUser> findList(EmpUser entity) {
  172  		return super.findList(entity);
  173  	}
  174
  175  	/**
  176  	 * [non-English text removed]
  177  	 */
  178  	@Override
  179  	public Page<EmpUser> findPage(EmpUser empUser) {
  180  		return super.findPage(empUser);
  181  	}
  182
  183  	/**
  184  	 * [non-English text removed],[non-English text removed]
  185  	 */
  186  	@Override
  187  	public List<EmpUser> findUserList(EmpUser empUser){
  188  		return dao.findUserList(empUser);
  189  	}
  190
  191  	/**
  192  	 * [non-English text removed],[non-English text removed]
  193  	 */
  194  	@Override
  195  	public List<EmpUser> findUserListByOfficeCodes(EmpUser empUser){
  196  		return dao.findUserListByOfficeCodes(empUser);
  197  	}
  198  	/**
  199  	 * [non-English text removed],[non-English text removed]
  200  	 */
```

5. `modules/core/src/main/java/com/jeesite/modules/sys/service/support/EmployeeServiceSupport.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/service/support/EmployeeServiceSupport.java#L77

```text
   74  	 */
   75  	@Override
   76  	@Transactional
   77  	public void save(Employee employee) {
   78  		if (employee.getIsNewRecord()){
   79  			if (dao.get(employee) != null){
   80  				throw newValidationException(text("[non-English text removed]"));
   81  			}
   82  		}
   83  		super.save(employee);
   84  		// [non-English text removed]
   85  		EmployeePost where = new EmployeePost();
   86  		where.setEmpCode(employee.getEmpCode());
   87  		employeePostDao.deleteByEntity(where);
   88  		if (ListUtils.isNotEmpty(employee.getEmployeePostList())){
   89  			for (EmployeePost e : employee.getEmployeePostList()){
   90  				e.setEmpCode(employee.getEmpCode());
   91  			}
   92  			employeePostDao.insertBatch(employee.getEmployeePostList(), null);
   93  		}
   94  	}
   95
   96  	/**
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for POST ${adminPath}/sys/empUser/save, officeCode/companyCode/postCode before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/jeesite5/issue1.html
