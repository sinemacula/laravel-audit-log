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

## Implementation Anchors

- `src/Records/EventCode.php`: `of()`, `RESERVED_PREFIX`.

## Authoritative Tests

- `tests/Unit/Records/EventCodeTest.php` `testRefusesTheReservedPrefix`,
  `testAcceptsCodesThatOnlyResembleTheReservedPrefix`, `testTheReservedPrefixIsCheckedAfterTheGrammar`
- `tests/Unit/Documentation/DocumentationTest.php` `testEveryReservedPrefixIsInTheVocabulary`,
  `testThePackagePrefixIsTheOneEventCodesReserve`, `testEveryShippedCodeIsUnderAReservedPrefix`,
  `testEveryExampleCodeIsValidAndNeutral`

## Change Triggers

Update this note when any of the following change:

- the code grammar or its length
- a reserved prefix, or which prefixes are enforced in code
- a code the package ships, or the OWASP names a prefix maps to
