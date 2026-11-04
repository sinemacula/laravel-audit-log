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
  a caller's code under it is refused by `EventCode::of()`, and only `Querying\Enums\PackageActivity` mints one,
  through `EventCode::package()`. `EventCode::forReading()` accepts one to look for, so a filter, a description or a
  test's assertion can name it, and nothing is ever recorded under a code made that way. The others are reserved by
  convention for the codes the package's own capture of Laravel's events and the integrations registered through its
  mapping seam record.
- Only the exact prefix is reserved: `audit_logs.pruned` and `app.audit_log.pruned` are ordinary codes.
- Any other prefix belongs to the application, such as `invoice.` or `user.`; its codes are its own to name and
  define.
- Every code the package ships is under a reserved prefix and is named here when it ships.
- The package defines its own codes while the application boots, before anything is recorded, so an application or an
  integration that defines one of them differently is refused at boot. The `audit_log.` codes are in the catalogue from
  the moment it is made, before any registration and whatever the freeze. An integration records its own activity
  under codes it defines, never under the package's.
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

The package records the first eleven codes when it captures Laravel's own authentication and authorisation events. Each
is defined by `Capture\Enums\CapturedActivity`, version 1, in the `security` category, and drops every property it does
not list. The actor and the subject are read from the event, never from the authenticated user: "none, explicitly" means
no actor is recorded and no contributor fills one in.

The package records the twelve `audit_log.` codes of its own activity: five on its read path, as [the reading
guide](../guides/reading.md) sets out, four of its lifecycle's prunes, holds, releases and imports, and three of its
owners' keys: an erasure, a rewrap and a reinstatement. Each is defined by `Querying\Enums\PackageActivity`, version 1,
in the `audit` category, and drops every property it does not list, so each row's properties are exactly the ones its
definition retains, in the order its record gives them. None of the lifecycle's codes, and none of the keys', is a
read. A read path's code is recorded by the viewer, in the tenant of a scope that sees exactly one and otherwise in
none; a lifecycle or key code is recorded once its operation has committed, by the operator the operation's authority
names, none for a prune, and in no tenant, explicitly. An owner is never the subject of the record of their own
erasure or reinstatement: it is named only by its keyed fingerprint and the id of the key that keyed it.

A page's `reveal` is whether its scope revealed the encrypted fields, and its `fields` counts the encrypted fragments
it showed by what each showed: `encrypted`, `erased`, `revealed` and `unreadable`. A denied or failed page showed
nothing, and counts none. An erasure's `blocked` holds at most 50 reasons, each `held:` and a hold's id,
`preserved:` and a category, or `unverified`, sorted bytewise, with any further ones counted under `_other`.

`audit_log.trail_exported` is protected: retention never prunes it. Every other code, the other `audit_log.` codes
included, follows its category's retention.

| Code                                      | Source                                                                | Outcome                        | Actor                                 | Subject                        | Properties kept                                                                                                                                                                                 |
|-------------------------------------------|-----------------------------------------------------------------------|--------------------------------|---------------------------------------|--------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `authentication.signed_in`                | `Login`                                                               | `success`                      | the user                              | the user                       | `remember`                                                                                                                                                                                      |
| `authentication.session_restored`         | `Login`, when the named guard is a `SessionGuard` and `viaRemember()` | `success`                      | the user                              | the user                       | `remember`                                                                                                                                                                                      |
| `authentication.sign_in_failed`           | `Failed`                                                              | `failure`                      | none, explicitly                      | the user when found, else none | none; the identifier is hashed                                                                                                                                                                  |
| `authentication.signed_out`               | `Logout`, `CurrentDeviceLogout`                                       | `success`                      | the user, or none                     | the user, or none              | none                                                                                                                                                                                            |
| `authentication.signed_out_other_devices` | `OtherDeviceLogout`                                                   | `success`                      | the user, or none                     | the user, or none              | none                                                                                                                                                                                            |
| `authentication.locked_out`               | `Lockout`                                                             | `denied`                       | none, explicitly                      | none                           | none; the IP, and the identifier hashed                                                                                                                                                         |
| `account.registered`                      | `Registered`                                                          | `success`                      | the user                              | the user                       | none                                                                                                                                                                                            |
| `account.email_verified`                  | `Verified`                                                            | `success`                      | the user                              | the user                       | none                                                                                                                                                                                            |
| `account.password_reset`                  | `PasswordReset`                                                       | `success`                      | the user                              | the user                       | none                                                                                                                                                                                            |
| `account.password_reset_requested`        | `PasswordResetLinkSent`                                               | `success`                      | none, explicitly                      | the user                       | none                                                                                                                                                                                            |
| `authorization.gate_denied`               | `GateEvaluated`, for a denial                                         | `denied`                       | the event's user, or none, explicitly | none                           | `ability`, `arguments`, `argument_count`                                                                                                                                                        |
| `audit_log.trail_read`                    | the read path                                                         | `success`, `denied`, `failure` | the viewer                            | none                           | `purpose`, `query_fingerprint`, `scope_fingerprint`, `fingerprint_key`, `policy`, `page`, `per_page`, `returned`, `reveal`, `fields`, `outcome`                                                 |
| `audit_log.trail_counted`                 | the read path                                                         | `success`, `denied`, `failure` | the viewer                            | none                           | `purpose`, `query_fingerprint`, `scope_fingerprint`, `fingerprint_key`, `policy`, `returned`, `outcome`                                                                                         |
| `audit_log.trail_exported`                | the read path                                                         | `success`, `denied`, `failure` | the viewer                            | none                           | `purpose`, `query_fingerprint`, `scope_fingerprint`, `fingerprint_key`, `policy`, `format`, `returned`, `file_sha256`, `outcome`                                                                |
| `audit_log.export_verified`               | the read path                                                         | `success`, `denied`, `failure` | the viewer                            | none                           | `purpose`, `scope_fingerprint`, `fingerprint_key`, `policy`, `export_entry`, `verdict`, `findings`, `outcome`                                                                                   |
| `audit_log.export_publish_failed`         | the read path                                                         | `failure`                      | the viewer                            | none                           | `export_entry`, `outcome`                                                                                                                                                                       |
| `audit_log.pruned`                        | a prune run                                                           | `success`, `failure`           | none, explicitly                      | none                           | `operation_id`, `status`, `policy_version`, `deleted`, `seals`, `held`, `pending_delivery`, `skipped_seals`, `categories`, `tenants_affected`, `outcome`                                        |
| `audit_log.held`                          | a hold placed                                                         | `success`                      | the authority's operator              | none                           | `operation_id`, `hold_id`, `basis`, `scope_digest`, `review_by`, `authority_reason`, `outcome`                                                                                                  |
| `audit_log.released`                      | a hold released                                                       | `success`, `denied`            | the authority's operator              | none                           | `operation_id`, `hold_id`, `authority_reason`, `outcome`                                                                                                                                        |
| `audit_log.imported`                      | an import                                                             | `success`, `failure`           | the authority's operator              | none                           | `operation_id`, `batch_id`, `source_id`, `format`, `status`, `lines_read`, `imported`, `duplicates`, `conflicts`, `rejected`, `hold_id`, `authority_reason`, `outcome`                          |
| `audit_log.subject_erased`                | an erasure                                                            | `success`, `denied`, `failure` | the authority's operator              | none                           | `operation_id`, `erasure_id`, `owner_fingerprint`, `fingerprint_key`, `status`, `keys_destroyed`, `keys_kept`, `entries_affected`, `blocked`, `pending_accepted`, `authority_reason`, `outcome` |
| `audit_log.keys_rewrapped`                | a rewrap                                                              | `success`, `failure`           | the authority's operator              | none                           | `operation_id`, `status`, `keys_rewrapped`, `keys_rotated`, `keys_skipped`, `wrap_key_id`, `batches`, `authority_reason`, `outcome`                                                             |
| `audit_log.keys_reinstated`               | a reinstatement                                                       | `success`, `denied`            | the authority's operator              | none                           | `operation_id`, `reinstatement_id`, `owner_fingerprint`, `fingerprint_key`, `generation_floor`, `authority_reason`, `outcome`                                                                   |

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

## Terminology

| Term          | Meaning                                                                                                                                                                                  |
|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| journal       | the lifecycle's chained, signed rows of every policy, prune run, prune, hold, release, import, erasure, reinstatement, rewrap and restore reconciliation; every seal commits to its head |
| hold          | a scope of entries retention never prunes while the hold is active, placed and released through the journal                                                                              |
| prune run     | one run of `audit-log:prune`: its start row, the prune row of each chunk it committed, and its finish row                                                                                |
| tombstone     | a sealed member whose entry is gone and whose prune a valid record covers: a pruned id, which a re-delivery completes as pruned and never inserts again                                  |
| erasure       | the destruction of an owner's keys, so every fragment sealed under them reads `erased`, journalled with the owner's keyed fingerprint                                                    |
| key unit      | what an owner's key is made for: the owner, the tenant of the records it seals, or none, and their definitions' category, so different obligations never share a key                     |
| generation    | one key of a unit, numbered from 1; a new generation opens after a rotation or a reinstatement, and an erased one never reopens                                                          |
| key use       | the derived, append-only row saying which key sealed a field of which entry, through which an erasure and `holdingDataOf()` find an owner's entries                                      |
| marker        | an owner's erasure or reinstatement, with the generation floor every later key of the owner is created above                                                                             |
| reinstatement | letting an erased owner have keys again, above the floor its erasure set, journalled; it makes no destroyed key readable again                                                           |
| revoked       | what an erasure achieves in the live store when it commits; erasure complete is the operator's procedure reaching every other copy                                                       |
| rewrap        | sealing the owners' keys again under the current wrapping key, journalled per batch, without changing what any fragment holds                                                            |
| reveal        | a scope's grant to read the encrypted fields of the entries it sees through the field reader, recorded on each page it reads                                                             |

## Implementation Anchors

- `src/Records/EventCode.php`: `of()`, `package()`, `forReading()`, `RESERVED_PREFIX`.
- `src/Capture/Enums/CapturedActivity.php`: `definition()`.
- `src/Querying/Enums/PackageActivity.php`: `definition()`, `isRead()`, `isProtected()`.
- `src/Definitions/EventCatalogue.php`: `__construct()`.
- `src/Capture/Enums/ModelEvent.php`: `codeFor()`, `eloquentEvent()`.

## Authoritative Tests

- `tests/Unit/Records/EventCodeTest.php` `testRefusesTheReservedPrefix`,
  `testAcceptsCodesThatOnlyResembleTheReservedPrefix`, `testTheReservedPrefixIsCheckedAfterTheGrammar`,
  `testPackageMintsAReservedCode`, `testOfStillRefusesTheReservedPrefix`, `testForReadingAcceptsAReservedCode`,
  `testForReadingStillChecksTheGrammarAndLength`
- `tests/Unit/Querying/Enums/PackageActivityTest.php` `testTheStoredValues`, `testEachIsUnderTheReservedPrefix`,
  `testEachDefinitionIsVersionOneInTheAuditCategoryDroppingWhatItDoesNotList`,
  `testEachLifecycleDefinitionKeepsExactlyItsProperties`, `testTheErasureCodesKeepExactlyTheirProperties`,
  `testTheTrailReadKeepsItsRevealAndFieldCounts`, `testTheReadPathsReadsAreReads`, `testNoLifecycleCodeIsARead`,
  `testNoPrivacyCodeIsAReadOrProtected`, `testOnlyTheExportIsProtected`
- `tests/Unit/Definitions/EventCatalogueTest.php` `testThePackageDefinitionsAreThereFromTheStart`,
  `testANewCatalogueHoldsOnlyThePackageDefinitions`, `testThePackageDefinitionsSurviveTheFreeze`
- `tests/Unit/Capture/Enums/CapturedActivityTest.php` `testTheCodesAreTheVocabularys`, `testEveryCaseDefinesItsOwnCode`,
  `testEveryDefinitionIsSecurityVersionOneAndDropsUnlisted`, `testTheSignInsRetainOnlyRemember`,
  `testTheGateDenialRetainsTheAbilityAndItsArguments`, `testTheOtherCodesRetainNothing`,
  `testTheCatalogueAcceptsTheEnum`, `testADifferentDefinitionOfAPackageCodeIsRefused`
- `tests/Unit/Capture/Enums/ModelEventTest.php` `testTheValues`, `testCodeForPutsTheSuffixAfterThePrefix`,
  `testTheLongestSegmentFitsTheCodeColumn`, `testEachEloquentEvent`
- `tests/Unit/Documentation/DocumentationTest.php` `testEveryReservedPrefixIsInTheVocabulary`,
  `testThePackagePrefixIsTheOneEventCodesReserve`, `testEveryShippedCodeIsUnderAReservedPrefix`,
  `testEveryExampleCodeIsValidAndNeutral`, `testEachPackageCodesRowKeepsItsDefinitionsProperties`
- `tests/Unit/Documentation/TranslationsTest.php` `testEveryShippedCodeHasATitle`, `testTheWalkFindsBothDefiningEnums`

## Change Triggers

Update this note when any of the following change:

- the code grammar or its length
- a reserved prefix, or which prefixes are enforced in code
- a code the package ships, its title, or the OWASP names a prefix maps to
- how the package's own codes are minted, or what may look one up
- what a package code is captured from, its outcome, its actor or subject, or the properties it keeps
- which package code retention never prunes
- a term the terminology defines
- what a key unit, a generation, a key use or a marker is
- a model code's suffix, the grammar of the segment a model is watched as, or the segments it may not be
