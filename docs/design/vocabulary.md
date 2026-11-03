# Vocabulary

## Purpose

This note records how event codes are named, and which prefixes are reserved. A code is a stable dotted name for what
happened (`invoice.approved`), chosen once and never derived from a class name, so renaming or moving a class never
changes the trail, and every reader, export and retention policy can rely on it. The OWASP Logging Vocabulary's codes
are not used verbatim, because they do not extend to the catalogue an application and its integrations need; instead,
each reserved prefix maps to the OWASP names it covers, so a record can be translated to that vocabulary when it is
exported.

## Invariants

- A code is lower-case dotted segments, each a letter followed by letters, digits or underscores, in at least two
  segments and at most 191 bytes (`EventCode::MAX_BYTES`), as `record-model.md` sets out.
- The prefixes in the table below are reserved. Only `audit_log.` is enforced in code (`EventCode::RESERVED_PREFIX`):
  a caller's code under it is refused. The others are reserved by convention for the codes the package's own capture
  of Laravel's events and the integrations registered through its mapping seam record.
- Only the exact prefix is reserved: `audit_logs.pruned` and `app.audit_log.pruned` are ordinary codes.
- Any other prefix belongs to the application, such as `invoice.` or `user.`; its codes are its own to name and
  define.
- Every code the package ships is under a reserved prefix and is named here when it ships.
- The package defines its own codes while the application boots, before anything is recorded, so an application or an
  integration that defines one of them differently is refused at boot. An integration records its own activity under
  codes it defines, never under the package's.
- A model's codes are under the segment it is watched as, which is never a reserved prefix's segment, so a model's
  change never collides with a code the package or an integration records.
- A record of access to sensitive data maps to `sensitive_read`, and other sensitive operations to `sensitive_create`,
  `sensitive_update` and `sensitive_delete`, whatever the application's code for them.

## Success Path

- The application names its codes under its own prefixes, for instance as the cases of an enum defining them (see
  `event-definitions.md`).
- The package's capture and the integrations record their codes under the reserved prefixes, so they never collide
  with the application's.
- An export translates a code to the OWASP names its prefix maps to, when it needs them.

## Failure / Edge Cases

- A caller's code under `audit_log.` is refused with an `\InvalidArgumentException`, after the code's grammar is
  checked, so `audit_log.` alone is refused for its grammar.
- A caller's code under any other reserved prefix is accepted, since only `audit_log.` is enforced; an application
  that records under one risks colliding with codes the package or an integration records later.

## Grammar

| Part    | Rule                                                                    |
|---------|-------------------------------------------------------------------------|
| segment | a lower-case letter, then lower-case letters, digits or underscores     |
| code    | at least two segments joined by `.`                                     |
| length  | at most 191 bytes                                                       |
| source  | a string, or the value of a string-backed enum case; never a class name |

## Reserved Prefixes

| Prefix            | Activity                                                                  | OWASP Logging Vocabulary                                                                                                                                                                                                                                                                            |
|-------------------|---------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `authentication.` | signing in and out, failed sign-ins, lockouts, credentials                | `authn_login_success`, `authn_login_successafterfail`, `authn_login_fail`, `authn_login_fail_max`, `authn_login_lock`, `authn_password_change`, `authn_password_change_fail`, `authn_token_created`, `authn_token_revoked`, `authn_token_reuse`, `authn_token_delete`, `excess_rate_limit_exceeded` |
| `session.`        | sessions created, renewed, expired and ended                              | `session_created`, `session_renewed`, `session_expired`, `session_use_after_expire`, `session_logout`                                                                                                                                                                                               |
| `account.`        | accounts registered, verified, changed, archived and deleted              | `user_created`, `user_updated`, `user_archived`, `user_deleted`                                                                                                                                                                                                                                     |
| `authorization.`  | access decisions and grants                                               | `authz_fail`, `authz_change`, `authz_admin`, `privilege_permissions_changed`                                                                                                                                                                                                                        |
| `mfa.`            | second factors enrolled, challenged, verified and failed                  | `authn_login_success`, `authn_login_fail`, `authn_token_created`, `authn_token_revoked`                                                                                                                                                                                                             |
| `sso.`            | sign-in through an external identity provider                             | `authn_login_success`, `authn_login_fail`, `authn_token_created`                                                                                                                                                                                                                                    |
| `audit_log.`      | the package's own activity: pruning, sealing, reading, exporting, erasing | `sensitive_read`, `sensitive_delete`, `sys_monitor_disabled`, `sys_monitor_enabled`                                                                                                                                                                                                                 |

## Package Codes

The package records these codes when it captures Laravel's own authentication and authorisation events. Each is defined
by `Capture\Enums\CapturedActivity`, version 1, in the `security` category, and drops every property it does not list.
The actor and the subject are read from the event, never from the authenticated user: "none, explicitly" means no actor
is recorded and no contributor fills one in.

| Code                                      | Captured from                                                         | Outcome   | Actor                                 | Subject                        | Properties kept                          |
|-------------------------------------------|-----------------------------------------------------------------------|-----------|---------------------------------------|--------------------------------|------------------------------------------|
| `authentication.signed_in`                | `Login`                                                               | `success` | the user                              | the user                       | `remember`                               |
| `authentication.session_restored`         | `Login`, when the named guard is a `SessionGuard` and `viaRemember()` | `success` | the user                              | the user                       | `remember`                               |
| `authentication.sign_in_failed`           | `Failed`                                                              | `failure` | none, explicitly                      | the user when found, else none | none; the identifier is hashed           |
| `authentication.signed_out`               | `Logout`, `CurrentDeviceLogout`                                       | `success` | the user, or none                     | the user, or none              | none                                     |
| `authentication.signed_out_other_devices` | `OtherDeviceLogout`                                                   | `success` | the user, or none                     | the user, or none              | none                                     |
| `authentication.locked_out`               | `Lockout`                                                             | `denied`  | none, explicitly                      | none                           | none; the IP, and the identifier hashed  |
| `account.registered`                      | `Registered`                                                          | `success` | the user                              | the user                       | none                                     |
| `account.email_verified`                  | `Verified`                                                            | `success` | the user                              | the user                       | none                                     |
| `account.password_reset`                  | `PasswordReset`                                                       | `success` | the user                              | the user                       | none                                     |
| `account.password_reset_requested`        | `PasswordResetLinkSent`                                               | `success` | none, explicitly                      | the user                       | none                                     |
| `authorization.gate_denied`               | `GateEvaluated`, for a denial                                         | `denied`  | the event's user, or none, explicitly | none                           | `ability`, `arguments`, `argument_count` |

`Attempting`, `Validated` and `Authenticated` are never captured.

## Model Codes

A model the application watches, through the boot-time watch registration, is recorded under its own segment, `as`,
then the change. `as` is one code segment of at most 177 bytes, so the longest code still fits 191, and it may not be
one of the reserved segments `authentication`, `session`, `account`, `authorization`, `mfa`, `sso` or `audit_log`. Each
code is defined for the watch, version 1, in the `change` category.

| Code                 | Recorded when                                                                 |
|----------------------|-------------------------------------------------------------------------------|
| `{as}.created`       | the model is inserted                                                         |
| `{as}.updated`       | the model is saved with a change to a watched field                           |
| `{as}.deleted`       | the model is deleted, or soft-deleted                                         |
| `{as}.restored`      | a soft-deleted model is restored: an update that clears its deleted-at column |
| `{as}.force_deleted` | the model is deleted for good, past its soft delete                           |

## Implementation Anchors

- `src/Records/EventCode.php`: `of()`, `RESERVED_PREFIX`.
- `src/Capture/Enums/CapturedActivity.php`: `definition()`.
- `src/Capture/Enums/ModelEvent.php`: `codeFor()`, `eloquentEvent()`.

## Authoritative Tests

- `tests/Unit/Records/EventCodeTest.php` `testRefusesTheReservedPrefix`,
  `testAcceptsCodesThatOnlyResembleTheReservedPrefix`, `testTheReservedPrefixIsCheckedAfterTheGrammar`
- `tests/Unit/Capture/Enums/CapturedActivityTest.php` `testTheCodesAreTheVocabularys`, `testEveryCaseDefinesItsOwnCode`,
  `testEveryDefinitionIsSecurityVersionOneAndDropsUnlisted`, `testTheSignInsRetainOnlyRemember`,
  `testTheGateDenialRetainsTheAbilityAndItsArguments`, `testTheOtherCodesRetainNothing`,
  `testTheCatalogueAcceptsTheEnum`, `testADifferentDefinitionOfAPackageCodeIsRefused`
- `tests/Unit/Capture/Enums/ModelEventTest.php` `testTheValues`, `testCodeForPutsTheSuffixAfterThePrefix`,
  `testTheLongestSegmentFitsTheCodeColumn`, `testEachEloquentEvent`
- `tests/Unit/Documentation/DocumentationTest.php` `testEveryReservedPrefixIsInTheVocabulary`,
  `testThePackagePrefixIsTheOneEventCodesReserve`, `testEveryShippedCodeIsUnderAReservedPrefix`,
  `testEveryExampleCodeIsValidAndNeutral`

## Change Triggers

Update this note when any of the following change:

- the code grammar or its length
- a reserved prefix, or which prefixes are enforced in code
- a code the package ships, or the OWASP names a prefix maps to
- what a package code is captured from, its outcome, its actor or subject, or the properties it keeps
- a model code's suffix, the grammar of the segment a model is watched as, or the segments it may not be
