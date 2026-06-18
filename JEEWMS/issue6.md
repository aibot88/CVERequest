---
title: "JEEWMS issue6: `/rest/tmsYwDingdanController` REST CRUD scope"
description: "JEEWMS has a missing authorization vulnerability in /rest/tmsYwDingdanController, rest/, roleId/functionId, roleId/userIds, /rest/user. An authenticated attacker can perform authorization-sensitive operations through /rest/tmsYwDingdanController, rest/, roleId/functionId, roleId/userIds, /rest/user without the required permission."
tags:
  - JEEWMS
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JEEWMS has a missing authorization vulnerability in /rest/tmsYwDingdanController, rest/, roleId/functionId, roleId/userIds, /rest/user. An authenticated attacker can perform authorization-sensitive operations through /rest/tmsYwDingdanController, rest/, roleId/functionId, roleId/userIds, /rest/user without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `/rest/tmsYwDingdanController, rest/, roleId/functionId, roleId/userIds, /rest/user`
- Affected authorization property: `sysOrgCode, do?datagrid, orgCode, sysOrgCode like %, ResourceUtil.getSessionUser().getCurrentDepart().getOrgCode(), getList(TmsYwDingdanEntity.class)`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through /rest/tmsYwDingdanController, rest/, roleId/functionId, roleId/userIds, /rest/user without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to /rest/tmsYwDingdanController, rest/, roleId/functionId, roleId/userIds, /rest/user with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `src/main/java/com/zzjee/tms/controller/TmsYwDingdanController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/com/zzjee/tms/controller/TmsYwDingdanController.java#L150

```text
  147  	 * @param dataGrid
  148  	 */
  149
  150  	@RequestMapping(params = "datagrid")
  151  	public void datagrid(TmsYwDingdanEntity tmsYwDingdan, HttpServletRequest request, HttpServletResponse response, DataGrid dataGrid) {
  152  		CriteriaQuery cq = new CriteriaQuery(TmsYwDingdanEntity.class, dataGrid);
  153  		//[non-English text removed]
  154  		org.jeecgframework.core.extend.hqlsearch.HqlGenerateUtil.installHql(cq, tmsYwDingdan, request.getParameterMap());
  155  		try{
  156  		//[non-English text removed]
  157  		String query_sdsj_begin = request.getParameter("sdsj_begin");
  158  		String query_sdsj_end = request.getParameter("sdsj_end");
  159  		if(StringUtil.isNotEmpty(query_sdsj_begin)){
  160  			cq.ge("sdsj", Integer.parseInt(query_sdsj_begin));
  161  		}
  162  		if(StringUtil.isNotEmpty(query_sdsj_end)){
  163  			cq.le("sdsj", Integer.parseInt(query_sdsj_end));
  164  		}
  165  		}catch (Exception e) {
  166  			// [non-English text removed]
  167  			throw new BusinessException(e.getMessage());
  168  		}
  169  		TSUser user = ResourceUtil.getSessionUser();
  170  		if(!StringUtil.isEmpty(user.getCurrentDepart().getOrgCode())){
  171  			cq.like("sysOrgCode",user.getCurrentDepart().getOrgCode()+"%");
  172
  173  		}
  174  		cq.eq("zhuangtai","[non-English text removed]");
  175  		cq.add();
  176  		this.tmsYwDingdanService.getDataGridReturn(cq, true);
  177  		TagUtil.datagrid(response, dataGrid);
  178  	}
  179
  180
```

2. `src/main/java/com/zzjee/tms/controller/TmsYwDingdanController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/com/zzjee/tms/controller/TmsYwDingdanController.java#L1074

```text
 1071  		j.setObj(files);
 1072  		return j;
 1073  	}
 1074  	@RequestMapping(method = RequestMethod.GET)
 1075  	@ResponseBody
 1076  	@ApiOperation(value="[non-English text removed]",produces="application/json",httpMethod="GET")
 1077  	public ResponseMessage<List<TmsYwDingdanEntity>> list() {
 1078  		List<TmsYwDingdanEntity> listTmsYwDingdans=tmsYwDingdanService.getList(TmsYwDingdanEntity.class);
 1079  		return Result.success(listTmsYwDingdans);
 1080  	}
 1081
 1082  	@RequestMapping(value = "/{id}", method = RequestMethod.GET)
```

3. `TmsYwDingdanEntity.c`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/TmsYwDingdanEntity.c
4. `src/main/java/com/zzjee/tms/controller/TmsYwDingdanController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/com/zzjee/tms/controller/TmsYwDingdanController.java#L1093

```text
 1090  		return Result.success(task);
 1091  	}
 1092
 1093  	@RequestMapping(method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
 1094  	@ResponseBody
 1095  	@ApiOperation(value="[non-English text removed]")
 1096  	public ResponseMessage<?> create(@ApiParam(name="[non-English text removed]")@RequestBody TmsYwDingdanEntity tmsYwDingdan, UriComponentsBuilder uriBuilder) {
 1097  		//[non-English text removed]JSR303 Bean Validator[non-English text removed],[non-English text removed]400[non-English text removed]json[non-English text removed].
 1098  		Set<ConstraintViolation<TmsYwDingdanEntity>> failures = validator.validate(tmsYwDingdan);
 1099  		if (!failures.isEmpty()) {
 1100  			return Result.error(JSONArray.toJSONString(BeanValidators.extractPropertyAndMessage(failures)));
 1101  		}
 1102
 1103  		//[non-English text removed]
 1104  		try{
 1105  			tmsYwDingdanService.save(tmsYwDingdan);
 1106  		} catch (Exception e) {
 1107  			e.printStackTrace();
 1108  			return Result.error("[non-English text removed]");
```

5. `src/main/java/com/zzjee/tms/controller/TmsYwDingdanController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/com/zzjee/tms/controller/TmsYwDingdanController.java#L1113

```text
 1110  		return Result.success(tmsYwDingdan);
 1111  	}
 1112
 1113  	@RequestMapping(value = "/{id}", method = RequestMethod.PUT, consumes = MediaType.APPLICATION_JSON_VALUE)
 1114  	@ResponseBody
 1115  	@ApiOperation(value="[non-English text removed]",notes="[non-English text removed]")
 1116  	public ResponseMessage<?> update(@ApiParam(name="[non-English text removed]")@RequestBody TmsYwDingdanEntity tmsYwDingdan) {
 1117  		//[non-English text removed]JSR303 Bean Validator[non-English text removed],[non-English text removed]400[non-English text removed]json[non-English text removed].
 1118  		Set<ConstraintViolation<TmsYwDingdanEntity>> failures = validator.validate(tmsYwDingdan);
 1119  		if (!failures.isEmpty()) {
 1120  			return Result.error(JSONArray.toJSONString(BeanValidators.extractPropertyAndMessage(failures)));
 1121  		}
 1122
 1123  		//[non-English text removed]
 1124  		try{
 1125  			tmsYwDingdanService.saveOrUpdate(tmsYwDingdan);
 1126  		} catch (Exception e) {
 1127  			e.printStackTrace();
 1128  			return Result.error("[non-English text removed]");
```

6. `src/main/java/com/zzjee/tms/controller/TmsYwDingdanController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/com/zzjee/tms/controller/TmsYwDingdanController.java#L1135

```text
 1132  		return Result.success("[non-English text removed]");
 1133  	}
 1134
 1135  	@RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
 1136  	@ResponseStatus(HttpStatus.NO_CONTENT)
 1137  	@ApiOperation(value="[non-English text removed]")
 1138  	public ResponseMessage<?> delete(@ApiParam(name="id",value="ID",required=true)@PathVariable("id") String id) {
 1139  		logger.info("delete[{}]" + id);
 1140  		// [non-English text removed]
 1141  		if (StringUtils.isEmpty(id)) {
 1142  			return Result.error("ID[non-English text removed]");
 1143  		}
```

7. `src/main/java/org/jeecgframework/core/interceptors/AuthInterceptor.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/core/interceptors/AuthInterceptor.java#L95

```text
   92          }
   93          if (excludeUrls.contains(requestPath)) {
   94              return true;
   95          } else if (moHuContain(excludeContainUrls, requestPath)) {
   96              return true;
   97          } else {
   98              // [non-English text removed]: [non-English text removed],[non-English text removed] URL([non-English text removed] online [non-English text removed])
   99              String clickFunctionId = request.getParameter("clickFunctionId");
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for /rest/tmsYwDingdanController, rest/, roleId/functionId, roleId/userIds, /rest/user before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JEEWMS/issue6.html
