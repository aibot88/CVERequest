---
title: "jeesite5 issue4: sys/post/save 岗位角色绑定"
description: "jeesite5 has a missing authorization vulnerability: sys/post/save 岗位角色绑定. 攻击者可用岗位编辑权限绕过用户/角色授权路径，为岗位绑定高权限角色。"
tags:
  - jeesite5
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

jeesite5 has a missing authorization vulnerability: sys/post/save 岗位角色绑定. 攻击者可用岗位编辑权限绕过用户/角色授权路径，为岗位绑定高权限角色。

- Attack precondition: 攻击者拥有 `sys:post:edit`；系统开启 `user.postRolePermi=true` 时该绑定会进入权限生效链路。
- Security impact: 攻击者可用岗位编辑权限绕过用户/角色授权路径，为岗位绑定高权限角色。

### 1.2 Exploit path

- 请求提交岗位信息和 `roleCodes`。

### 1.3 Key code evidence

1. `modules/core/src/main/java/com/jeesite/modules/sys/web/PostController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/PostController.java#L96

```text
   93  		return "modules/sys/postForm";
   94  	}
   95  
   96  	@RequiresPermissions("sys:post:edit")
   97  	@PostMapping(value = "save")
   98  	@ResponseBody
   99  	public String save(@Validated Post post, HttpServletRequest request) {
  100  		Post old = super.getWebDataBinderSource(request);
  101  		if (!"true".equals(checkPostName(old != null ? old.getPostName() : "", post.getPostName()))) {
  102  			return renderResult(Global.FALSE, text("保存岗位失败，岗位名称''{0}''已存在", post.getPostName()));
  103  		}
  104  		postService.save(post);
  105  		return renderResult(Global.TRUE, text("保存岗位''{0}''成功", post.getPostName()));
  106  	}
  107  
  108  	@RequiresPermissions("sys:post:edit")
```

2. `modules/core/src/main/java/com/jeesite/modules/sys/service/support/PostServiceSupport.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/service/support/PostServiceSupport.java#L88

```text
   85  	 */
   86  	@Override
   87  	@Transactional
   88  	public void save(Post post) {
   89  		if (post.getIsNewRecord()){
   90  			// 生成主键，并验证改主键是否存在，如存在则抛出验证信息
   91  			genIdAndValid(post, post.getViewCode());
   92  		}
   93  		super.save(post);
   94  		// 重新绑定岗位和角色之间的关系
   95  		if (StringUtils.isNotBlank(post.getPostCode()) && post.getRoleCodes() != null) {
   96  			PostRole where = new PostRole();
   97  			where.setPostCode(post.getPostCode());
   98  			postRoleDao.deleteByEntity(where);
   99  			List<PostRole> list = ListUtils.newArrayList();
  100  			for (String code : StringUtils.splitComma(post.getRoleCodes())) {
  101  				PostRole e = new PostRole();
  102  				e.setPostCode(post.getPostCode());
  103  				e.setRoleCode(code);
  104  				e.setIsNewRecord(true);
  105  				list.add(e);
  106  			}
  107  			if (ListUtils.isNotEmpty(list)) {
  108  				postRoleDao.insertBatch(list, null);
  109  			}
  110  		}
  111  		clearCache(post);
  112  	}
```

3. `modules/core/src/main/java/com/jeesite/modules/sys/web/SwitchController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/SwitchController.java#L98

```text
   95  	 * 切换岗位菜单（用户->岗位->角色）v4.9.2
   96  	 */
   97  	@RequiresPermissions("user")
   98  	@RequestMapping(value = {"switchPost","switchPost/{postCode}"})
   99  	public String switchPost(@PathVariable(required=false) String postCode, HttpServletRequest request, HttpServletResponse response) {
  100  		Session session = UserUtils.getSession();
  101  		if (StringUtils.isNotBlank(postCode)){
  102  			// 只能设置当前用户的岗位，查询权限的时候系统也会二次验证当前用户岗位
  103  			if (EmpUtils.getEmployeePostList().stream().noneMatch((ep) ->
  104  					StringUtils.equals(postCode, ep.getPostCode()))){
  105  				return renderResult(response, Global.FALSE, text("没有权限切换到该岗位"));
  106  			}
  107  			// 开启 user.postRolePermi 参数后，才可以使用岗位关联角色过滤菜单权限
  108  			if (!Global.getConfigToBoolean("user.postRolePermi", "false")) {
  109  				return renderResult(response, Global.FALSE, text("请开启 user.postRolePermi 参数。"));
  110  			}
  111  			// 查询岗位关联的角色
  112  			PostRole where = new PostRole();
  113  			where.setPostCode(postCode);
  114  			where.sqlMap().loadJoinTableAlias("r");
  115  			Set<String> roleCodes = SetUtils.newHashSet();
  116  			postService.findPostRoleList(where).forEach(e -> {
  117  				if (e.getRole() != null && PostRole.STATUS_NORMAL.equals(e.getRole().getStatus())) {
  118  					roleCodes.add(e.getRoleCode());
  119  				}
  120  			});
  121  			if (roleCodes.isEmpty()){
  122  				roleCodes.add("__none__");
  123  			}
  124  			session.setAttribute("postCode", postCode);
  125  			session.setAttribute("roleCode", StringUtils.joinComma(roleCodes)); // 5.4.0+ 支持多个，逗号隔开
  126  		}else{
  127  			session.removeAttribute("postCode");
  128  			session.removeAttribute("roleCode");
  129  		}
  130  		UserUtils.removeCache(UserUtils.CACHE_AUTH_INFO+"_"+session.getId());
```

4. `modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java#L530

```text
  527  						roleCodes.add(e.getRoleCode());
  528  					}
  529  				});
  530  				if (roleCodes.isEmpty()){
  531  					roleCodes.add("__none__");
  532  				}
  533  				session.setAttribute("roleCode", StringUtils.joinComma(roleCodes)); // 5.4.0+ 支持多个，逗号隔开
  534  			} else {
  535  				session.removeAttribute("roleCode");
  536  			}
  537  		}
  538  		UserUtils.removeCache(UserUtils.CACHE_AUTH_INFO+"_"+session.getId());
  539  		if (ServletUtils.isAjaxRequest(request)) {
  540  			return renderResult(response, Global.TRUE, text("部门切换成功"));
  541  		}
  542  		return REDIRECT + adminPath + "/index";
  543  	}
  544  	
  545  }
```

5. `modules/core/src/main/resources/config/jeesite-core.yml`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/resources/config/jeesite-core.yml#L223

```text
  220    # 二级管理员的控制权限类型（1拥有的权限 2管理的权限，管理功能包括：用户管理、组织机构、公司管理等）（v4.1.5+）
  221    adminCtrlPermi: 2
  222  
  223    # 是否启用岗位角色，开启后将 用户->岗位->关联角色，纳入菜单和权限管理 v5.9.2
  224    postRolePermi: false
  225  
  226    # 是否启用切换部门功能，再开启启用岗位角色后可支持 用户->附属部门->岗位->关联角色，纳入菜单和权限管理 v5.10.1
  227    switchOffice: false
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

保存岗位角色时校验 `roleCodes` 必须是当前操作者可授予角色集合的子集；或将岗位角色绑定纳入与用户角色授权同级的权限控制。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/jeesite5/issue4.html
