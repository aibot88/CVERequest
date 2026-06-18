---
title: "onedev issue1: Codex PullRequestAssignment"
description: "onedev has a missing authorization vulnerability in POST /pull-request-assignments, /tod/create-pull-request, /tod/edit-pull-request, user/request. An authenticated attacker can perform authorization-sensitive operations through POST /pull-request-assignments, /tod/create-pull-request, /tod/edit-pull-request, user/request without the required permission."
tags:
  - onedev
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

onedev has a missing authorization vulnerability in POST /pull-request-assignments, /tod/create-pull-request, /tod/edit-pull-request, user/request. An authenticated attacker can perform authorization-sensitive operations through POST /pull-request-assignments, /tod/create-pull-request, /tod/edit-pull-request, user/request without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `POST /pull-request-assignments, /tod/create-pull-request, /tod/edit-pull-request, user/request`
- Affected authorization property: `WriteCode, PullRequestAssignment.user, canModifyPullRequest, create, SecurityUtils.canModifyPullRequest(pullRequest), assignmentService.create(assignment)`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through POST /pull-request-assignments, /tod/create-pull-request, /tod/edit-pull-request, user/request without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to POST /pull-request-assignments, /tod/create-pull-request, /tod/edit-pull-request, user/request with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `server-core/src/main/java/io/onedev/server/rest/resource/PullRequestAssignmentResource.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/rest/resource/PullRequestAssignmentResource.java#L49

```text
   46
   47  	@Api(order=200, description="Create new pull request assignment")
   48  	@POST
   49  	public Long create(PullRequestAssignment assignment) {
   50  		PullRequest pullRequest = assignment.getRequest();
   51  		if (!SecurityUtils.canModifyPullRequest(pullRequest)) {
   52  			throw new UnauthorizedException();
```

2. `SecurityUtils.c`

Evidence location: https://code.onedev.io/onedev/server/SecurityUtils.c
3. `assignmentService.c`

Evidence location: https://code.onedev.io/onedev/server/assignmentService.c
4. `server-core/src/main/java/io/onedev/server/service/impl/DefaultPullRequestAssignmentService.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/service/impl/DefaultPullRequestAssignmentService.java#L26

```text
   23
   24  	@Transactional
   25  	@Override
   26  	public void create(PullRequestAssignment assignment) {
   27  		Preconditions.checkState(assignment.isNew());
   28  		dao.persist(assignment);
   29
```

5. `server-core/src/main/java/io/onedev/server/security/SecurityUtils.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/security/SecurityUtils.java#L645

```text
  642
  643  	public static String getPrevPrincipal() {
  644  		PrincipalCollection prevPrincipals = SecurityUtils.getSubject().getPreviousPrincipals();
  645  		if (prevPrincipals != null)
  646  			return (String) prevPrincipals.getPrimaryPrincipal();
  647  		else
  648  			return PRINCIPAL_ANONYMOUS;
```

6. `server-core/src/main/java/io/onedev/server/web/component/pullrequest/assignment/AssigneeProvider.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/web/component/pullrequest/assignment/AssigneeProvider.java#L28

```text
   25  		PullRequest request = getPullRequest();
   26  		UserService userService = OneDev.getInstance(UserService.class);
   27
   28  		List<User> users = new ArrayList<>(SecurityUtils.getAuthorizedUsers(request.getProject(), new WriteCode()));
   29
   30  		users.removeAll(request.getAssignees());
   31
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for POST /pull-request-assignments, /tod/create-pull-request, /tod/edit-pull-request, user/request before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/onedev/issue1.html
