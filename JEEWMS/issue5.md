---
title: "JEEWMS issue5: `/rest/user` CRUD"
description: "JEEWMS has a missing authorization vulnerability in /rest/user, rest/, save/saveOrUpdate/deleteEntityById, /user, ^rest/[a-zA-Z0-9_/]+$. An authenticated attacker can perform authorization-sensitive operations through /rest/user, rest/, save/saveOrUpdate/deleteEntityById, /user, ^rest/[a-zA-Z0-9_/]+$ without the required permission."
tags:
  - JEEWMS
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JEEWMS has a missing authorization vulnerability in /rest/user, rest/, save/saveOrUpdate/deleteEntityById, /user, ^rest/[a-zA-Z0-9_/]+$. An authenticated attacker can perform authorization-sensitive operations through /rest/user, rest/, save/saveOrUpdate/deleteEntityById, /user, ^rest/[a-zA-Z0-9_/]+$ without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `/rest/user, rest/, save/saveOrUpdate/deleteEntityById, /user, ^rest/[a-zA-Z0-9_/]+$`
- Affected authorization property: `AuthInterceptor, TSUser, UserController.saveUser, saveOrUpdate`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through /rest/user, rest/, save/saveOrUpdate/deleteEntityById, /user, ^rest/[a-zA-Z0-9_/]+$ without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to /rest/user, rest/, save/saveOrUpdate/deleteEntityById, /user, ^rest/[a-zA-Z0-9_/]+$ with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java#L33

```text
   30   *
   31   * @author liuht
   32   */
   33  @Controller
   34  @RequestMapping(value = "/user")
   35  public class UserRestController {
   36
   37  	@Autowired
   38  	private UserService userService;
```

2. `src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java#L69

```text
   66  		return new ResponseEntity(task, HttpStatus.OK);
   67  	}
   68
   69  	@RequestMapping(method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
   70  	@ResponseBody
   71  	public ResponseEntity<?> create(@RequestBody TSUser user, UriComponentsBuilder uriBuilder) {
   72  		//[non-English text removed]JSR303 Bean Validator[non-English text removed],[non-English text removed]400[non-English text removed]json[non-English text removed].
   73  		Set<ConstraintViolation<TSUser>> failures = validator.validate(user);
   74  		if (!failures.isEmpty()) {
   75  			return new ResponseEntity(BeanValidators.extractPropertyAndMessage(failures), HttpStatus.BAD_REQUEST);
   76  		}
   77
   78  		//[non-English text removed]
   79  		userService.save(user);
   80
   81  		//[non-English text removed]Restful[non-English text removed],[non-English text removed]url, [non-English text removed]id[non-English text removed].
   82  		String id = user.getId();
```

3. `src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java#L90

```text
   87  		return new ResponseEntity(headers, HttpStatus.CREATED);
   88  	}
   89
   90  	@RequestMapping(value = "/{id}", method = RequestMethod.PUT, consumes = MediaType.APPLICATION_JSON_VALUE)
   91  	public ResponseEntity<?> update(@RequestBody TSUser user) {
   92  		//[non-English text removed]JSR303 Bean Validator[non-English text removed],[non-English text removed]400[non-English text removed]json[non-English text removed].
   93  		Set<ConstraintViolation<TSUser>> failures = validator.validate(user);
   94  		if (!failures.isEmpty()) {
   95  			return new ResponseEntity(BeanValidators.extractPropertyAndMessage(failures), HttpStatus.BAD_REQUEST);
   96  		}
   97
   98  		//[non-English text removed]
   99  		userService.saveOrUpdate(user);
  100
  101  		//[non-English text removed]Restful[non-English text removed],[non-English text removed]204[non-English text removed], [non-English text removed]. [non-English text removed]200[non-English text removed].
  102  		return new ResponseEntity(HttpStatus.NO_CONTENT);
```

4. `src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/org/jeecgframework/web/rest/controller/UserRestController.java#L105

```text
  102  		return new ResponseEntity(HttpStatus.NO_CONTENT);
  103  	}
  104
  105  	@RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
  106  	@ResponseStatus(HttpStatus.NO_CONTENT)
  107  	public void delete(@PathVariable("id") String id) {
  108  		userService.deleteEntityById(TSUser.class, id);
  109  	}
  110  }
```

5. `src/main/java/org/jeecgframework/core/interceptors/AuthInterceptor.java`

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

Enforce server-side authorization for /rest/user, rest/, save/saveOrUpdate/deleteEntityById, /user, ^rest/[a-zA-Z0-9_/]+$ before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JEEWMS/issue5.html
