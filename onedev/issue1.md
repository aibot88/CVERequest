---
title: "onedev issue1: Codex PullRequestAssignment 授权上界缺失"
description: "onedev has a missing authorization vulnerability: Codex PullRequestAssignment 授权上界缺失. 被写入的用户会被后续 `canModifyPullRequest` 直接信任为 PR assignee，从而获得修改该 PR 的权限。影响包括改标题、描述、label、assignee、merge strategy 等；merge/run job 等路径另有额外检查，不在本结论中扩大。"
tags:
  - onedev
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

onedev has a missing authorization vulnerability: Codex PullRequestAssignment 授权上界缺失. 被写入的用户会被后续 `canModifyPullRequest` 直接信任为 PR assignee，从而获得修改该 PR 的权限。影响包括改标题、描述、label、assignee、merge strategy 等；merge/run job 等路径另有额外检查，不在本结论中扩大。

- Attack precondition: 攻击者能修改某个 PR，例如 PR submitter、已有 assignee，或具备 Manage Pull Requests；不要求攻击者或被授予用户具备目标项目 `WriteCode`。
- Security impact: 被写入的用户会被后续 `canModifyPullRequest` 直接信任为 PR assignee，从而获得修改该 PR 的权限。影响包括改标题、描述、label、assignee、merge strategy 等；merge/run job 等路径另有额外检查，不在本结论中扩大。

### 1.2 Exploit path

调用 `POST /pull-request-assignments`，或 TOD `/tod/create-pull-request`、`/tod/edit-pull-request`，把任意用户写入 `PullRequestAssignment.user`。

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

创建/同步 assignment 前校验 `SecurityUtils.canWriteCode(assignee.asSubject(), pullRequest.getProject())`，并在 REST、TOD、Web/service 统一入口复用同一校验。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/onedev/issue1.html
