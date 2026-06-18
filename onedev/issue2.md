---
title: "onedev issue2: Detector REST issue time tracking"
description: "onedev has a missing authorization vulnerability in GET /issue-works/{workId}, GET /issues/{id}, GET /issues, GET /issues/{id}/works, GET /issues/{id}/changes, /{id}/works. An authenticated attacker can read authorization-sensitive data that should be restricted."
tags:
  - onedev
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

onedev has a missing authorization vulnerability in GET /issue-works/{workId}, GET /issues/{id}, GET /issues, GET /issues/{id}/works, GET /issues/{id}/changes, /{id}/works. An authenticated attacker can read authorization-sensitive data that should be restricted.

- Attack precondition: Any authenticated user
- Affected endpoint: `GET /issue-works/{workId}, GET /issues/{id}, GET /issues, GET /issues/{id}/works, GET /issues/{id}/changes, /{id}/works`
- Affected authorization property: `AccessTimeTracking, canAccessIssue, getIssueMap, getChanges, issue.getChanges(), getWork`
- Security impact: An authenticated attacker can read authorization-sensitive data that should be restricted.

### 1.2 Exploit path

The attacker sends crafted requests to GET /issue-works/{workId}, GET /issues/{id}, GET /issues, GET /issues/{id}/works, GET /issues/{id}/changes, /{id}/works with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `server-core/src/main/java/io/onedev/server/rest/resource/IssueResource.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/rest/resource/IssueResource.java#L131

```text
  128      }
  129
  130  	@Api(order=200, exampleProvider = "getFieldsExample")
  131  	@Path("/{issueId}/fields")
  132      @GET
  133      public Map<String, Serializable> getFields(@PathParam("issueId") Long issueId) {
  134  		Issue issue = issueService.load(issueId);
```

2. `server-core/src/main/java/io/onedev/server/rest/resource/IssueResource.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/rest/resource/IssueResource.java#L171

```text
  168  		Issue issue = issueService.load(issueId);
  169      	if (!SecurityUtils.canAccessIssue(issue))
  170  			throw new UnauthorizedException();
  171      	return issue.getComments();
  172      }
  173
  174  	@Api(order=425)
```

3. `server-core/src/main/java/io/onedev/server/rest/resource/IssueWorkResource.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/rest/resource/IssueWorkResource.java#L46

```text
   43  	@Api(order=100)
   44  	@Path("/{workId}")
   45  	@GET
   46  	public IssueWork getWork(@PathParam("workId") Long workId) {
   47  		if (!subscriptionService.isSubscriptionActive())
   48  			throw new UnsupportedOperationException("This feature requires an active subscription");
   49  		IssueWork work = workService.load(workId);
```

4. `server-core/src/main/java/io/onedev/server/web/component/issue/activities/IssueActivitiesPanel.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/web/component/issue/activities/IssueActivitiesPanel.java#L151

```text
  148  				otherActivities.add(new IssueCommentActivity(comment));
  149  		}
  150
  151  		if (showWorkLog && getIssue().getProject().isTimeTracking()
  152  				&& WicketUtils.isSubscriptionActive()
  153  				&& canAccessTimeTracking(getIssue().getProject())) {
  154  			for (IssueWork work: getIssue().getWorks())
```

5. `SecurityUtils.c`

Evidence location: https://code.onedev.io/onedev/server/SecurityUtils.c

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for GET /issue-works/{workId}, GET /issues/{id}, GET /issues, GET /issues/{id}/works, GET /issues/{id}/changes, /{id}/works before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/onedev/issue2.html
