---
title: "jeesite5 issue1: empUser/save 组织/岗位重绑定"
description: "jeesite5 has a missing authorization vulnerability: empUser/save 组织/岗位重绑定. 攻击者可把员工重绑定到不可管理的公司、机构或岗位，污染组织/岗位权限边界；在岗位角色权限开启场景下，可能进一步影响后续 session 角色聚合。"
tags:
  - jeesite5
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

jeesite5 has a missing authorization vulnerability: empUser/save 组织/岗位重绑定. 攻击者可把员工重绑定到不可管理的公司、机构或岗位，污染组织/岗位权限边界；在岗位角色权限开启场景下，可能进一步影响后续 session 角色聚合。

- Attack precondition: 攻击者拥有 `sys:empUser:edit`，能够新增员工或编辑其数据范围内的员工。
- Security impact: 攻击者可把员工重绑定到不可管理的公司、机构或岗位，污染组织/岗位权限边界；在岗位角色权限开启场景下，可能进一步影响后续 session 角色聚合。

### 1.2 Exploit path

- Spring MVC 将请求参数绑定到 `EmpUser`。

### 1.3 Key code evidence

1. `EmpUser.employee.company.c`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/EmpUser.employee.company.c
2. `modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java#L185

```text
  182  		}
  183  		EmpUser old = super.getWebDataBinderSource(request);
  184  		if (!Global.TRUE.equals(userService.checkLoginCode(old != null ? old.getLoginCode() : "", empUser.getLoginCode()))) {
  185  			return renderResult(Global.FALSE, text("保存用户失败，登录账号''{0}''已存在", empUser.getLoginCode()));
  186  		}
  187  		if (StringUtils.isBlank(empUser.getEmployee().getEmpNo())){
  188  			empUser.getEmployee().setEmpNo(empUser.getLoginCode());
```

3. `modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java#L203

```text
  200  				return renderResult(Global.FALSE, text("启用岗位角色权限后，请在用户关联岗位中关联角色", empUser.getUserName()));
  201  			}
  202  		}else if (StringUtils.inString(op, Global.OP_ADD, Global.OP_AUTH) && subject.isPermitted("sys:empUser:authRole")){
  203  			empUserService.checkUserDataScope(empUser.getUserCode(), Global.getConfig("user.adminCtrlPermi", "2"));
  204  			userService.saveAuth(empUser);
  205  		}
  206  		return renderResult(Global.TRUE, text("保存用户''{0}''成功", empUser.getUserName()));
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
  163  			throw new ServiceException(text("没有权限使用该公司数据！"));
  164  		}
  165  	}
  166  
  167  	/**
  168  	 * 查询数据
  169  	 */
  170  	@Override
  171  	public List<EmpUser> findList(EmpUser entity) {
  172  		return super.findList(entity);
  173  	}
  174  
  175  	/**
  176  	 * 分页查询数据
  177  	 */
  178  	@Override
  179  	public Page<EmpUser> findPage(EmpUser empUser) {
  180  		return super.findPage(empUser);
  181  	}
  182  
  183  	/**
  184  	 * 查询全部用户，仅返回基本信息
  185  	 */
  186  	@Override
  187  	public List<EmpUser> findUserList(EmpUser empUser){
  188  		return dao.findUserList(empUser);
  189  	}
  190  	
  191  	/**
  192  	 * 根据部门编码查询用户，仅返回基本信息
  193  	 */
  194  	@Override
  195  	public List<EmpUser> findUserListByOfficeCodes(EmpUser empUser){
  196  		return dao.findUserListByOfficeCodes(empUser);
  197  	}
  198  	/**
  199  	 * 根据公司编码查询用户，仅返回基本信息
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
   80  				throw newValidationException(text("员工工号已存在"));
   81  			}
   82  		}
   83  		super.save(employee);
   84  		// 保存员工岗位
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

保存前逐项校验主机构、公司、岗位、附属机构和附属岗位均在当前操作者可管理范围内；任一越界则拒绝整个保存。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/jeesite5/issue1.html
