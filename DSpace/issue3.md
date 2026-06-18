---
title: "DSpace issue3: Registration Token Path Allows Arbitrary netid Binding"
description: "DSpace has a missing authorization vulnerability: Registration Token Path Allows Arbitrary netid Binding. Unauthorized write to `eperson.netid`, an authentication binding property used by external authentication integrations. This can pre-bind an account to an arbitrary unused external identity identifier"
tags:
  - DSpace
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

DSpace has a missing authorization vulnerability: Registration Token Path Allows Arbitrary netid Binding. Unauthorized write to `eperson.netid`, an authentication binding property used by external authentication integrations. This can pre-bind an account to an arbitrary unused external identity identifier

- Attack precondition: Registration is enabled. The attacker has a valid registration token for their email, provides a password, and chooses an unused `netid` value
- Security impact: Unauthorized write to `eperson.netid`, an authentication binding property used by external authentication integrations. This can pre-bind an account to an arbitrary unused external identity identifier

### 1.2 Exploit path

`POST /api/eperson/epersons?token=<token>` creates an EPerson from request body data. In the password-registration branch, the code validates token/email/password but does not call `canRegisterExternalAccount()` or enforce that request `netid` matches trusted token data. The request body `netid` is persisted via `setNetid()`

### 1.3 Key code evidence

1. `EPersonRestRepository.java`

Evidence location: EPersonRestRepository.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Ignore client-supplied `netid` in password registration, or require it to match trusted registration token data. Apply the same external-account validation regardless of whether a password is supplied

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/DSpace/issue3.html
