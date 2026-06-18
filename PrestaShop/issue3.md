---
title: "PrestaShop issue3: Legacy Webservice Body RBP Write Without Binding Authorization"
description: "PrestaShop has a missing authorization vulnerability in POST /api/specific_prices?id_shop=. The attacker can write authorization/ownership-related relationships in database entities, such as shop/customer/group-specific price rules, address ownership, cart ownership, or order relations. This can affect tenant boundaries, customer ownership, and pricing/authorization behavior"
tags:
  - PrestaShop
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

PrestaShop has a missing authorization vulnerability in POST /api/specific_prices?id_shop=. The attacker can write authorization/ownership-related relationships in database entities, such as shop/customer/group-specific price rules, address ownership, cart ownership, or order relations. This can affect tenant boundaries, customer ownership, and pricing/authorization behavior

- Attack precondition: Any authenticated user
- Affected endpoint: `POST /api/specific_prices?id_shop=`
- Affected authorization property: `specific_prices, addresses, carts, orders, webserviceChecks(), shopHasRight()`
- Security impact: The attacker can write authorization/ownership-related relationships in database entities, such as shop/customer/group-specific price rules, address ownership, cart ownership, or order relations. This can affect tenant boundaries, customer ownership, and pricing/authorization behavior

### 1.2 Exploit path

Use a permitted resource/method in the URL, but submit XML body fields that bind the created/updated object to unauthorized related resources or shops. Example class of request:

### 1.3 Key code evidence

1. `classes/webservice/WebserviceRequest.php`

Evidence location: classes/webservice/WebserviceRequest.php#L609
2. `classes/webservice/WebserviceRequest.php`

Evidence location: classes/webservice/WebserviceRequest.php#L844
3. `classes/webservice/WebserviceRequest.php`

Evidence location: classes/webservice/WebserviceRequest.php#L930
4. `classes/webservice/WebserviceRequest.php`

Evidence location: classes/webservice/WebserviceRequest.php#L1507
5. `classes/SpecificPrice.php`

Evidence location: classes/SpecificPrice.php#L36
6. `classes/SpecificPrice.php`

Evidence location: classes/SpecificPrice.php#L60
7. `classes/Address.php`

Evidence location: classes/Address.php#L137
8. `classes/Cart.php`

Evidence location: classes/Cart.php#L145
9. `classes/order/Order.php`

Evidence location: classes/order/Order.php#L229

## 2. Existing checks and why they fail

- Resource/method checks do not authorize body relationship targets. - Field validation accepts unsigned IDs and valid formats, but does not validate current key authorization over the referenced shop/customer/cart/address. - Shop right check is tied to request shop context, not every body-provided RBP field

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

For Webservice write operations, validate all body relationship fields against the Webservice key's authorized shops/resources before `add()` / `update()`. At minimum, reject body `id_shop` / `id_shop_group` outside the key's allowed shops and validate customer/address/cart/order references against the same shop and resource authorization scope

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/PrestaShop/issue3.html
