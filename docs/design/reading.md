# Reading And Access Control

## Purpose

This note records how the trail is read, for whom, and what a read leaves behind: the immutable query, the access
policy, the one compiler that turns a scope and the caller's filters into SQL, the signed cursor, the entry a viewer is
shown and the grant that reveals its encrypted fields, the record every read writes before anything it found leaves the
package, and the export that is journalled before it is published and verified later from its bundle. A read that is not
itself recorded, or that shows more than its scope, would make the log a way around the controls it records. How to read
the trail is in `docs/guides/reading.md`; what a PHP policy cannot stop is in `threat-model.md`.

## Invariants

- **Nothing is disclosed before its record is acknowledged.** No row, count, export file or verification result leaves
  the package until the read's own record has been stored, in sync mode, or committed to the outbox, in outbox mode,
  through the package's own write path, which is fail-closed and immediate whatever `failure.mode` says. A read that
  cannot be recorded throws `Querying\AuditReadRefusedException`, whose message names classes and connections, never a
  value, a statement or a binding, and which carries no previous exception.
- **A mistake in the code is refused before any query and is not recorded:** a terminal call without a viewer, a viewer
  that cannot be referenced, a malformed filter, a page size outside 1 to `read.max_per_page`, an export target that
  exists without `force` or whose filesystem cannot hold a hard link without it, an engine an export cannot read, and
  a malformed `export.chunk`. Everything after `Querying\ReadGate` lets a read in is
  recorded, success, denial or failure alike, but for the gate's own refusals and `ReadGate::confirmDurable()`'s just
  before the write, where no record could be durable, and which return nothing.
- **One compiler.** Every statement that reads entries for a viewer, a page, a count, an export's bound and chunks, and
  the export entry a verification looks up, is narrowed by `Access\ScopeCompiler` alone: `apply()`, `before()`,
  `after()` and `entry()`. The compiled form is tenant AND category AND about AND the caller's filters AND the cursor,
  each a grouped condition, so no `or` reaches past its own group and a caller's filter only narrows.
  `holdingDataOf()` compiles to an `EXISTS` over the key uses joined to the owner's keys, correlated on the entry, so
  it selects the entries holding a fragment the owner's keys sealed and narrows like any other filter. Column names,
  operators and the `like` escape character `!` are the compiler's own; every value is bound; times are bound in UTC
  with six fractional digits; no collation is applied, so ids compare in the type each engine migrated them as.
- **The scope algebra.** `Access\AccessScope` starts from `none()`, `all()` or `tenants()` and narrows through
  `withTenantless()`, `onlyCategories()`, `exceptCategories()` and `onlyAbout()`. References match as exact `(type, id)`
  pairs, never as lists of types and ids apart; tenantless means both tenant columns are `null`; `none()` absorbs every
  operation; an empty list denies and never means unrestricted; narrowing only intersects, so nothing widens.
  `revealingEncryptedFields()` grants the scope its encrypted fields: off on every starting scope, kept by every
  narrowing, part of the normalised form, the fingerprint and so the cursor's binding, and a denied scope stays denied
  and reveals nothing. A scope
  holds at most 100 tenants, 50 categories and 100 about-references. A denied scope, or one the filters cannot meet, is
  answered with a uniform empty result and no statement. `onlyAbout()` matches the actor or the subject only.
- **The cursor.** `v1.` and the key id, the payload `{pos: [occurred_at, id]}` and the MAC, each unpadded base64url, at
  most 512 bytes. The MAC is HMAC-SHA256 under a key HKDF derives from the ring key the key id names, with the info
  `sinemacula/audit-log:cursor:v1`, over the canonical binding of the version, the log's connection and table, the
  viewer, the purpose, the order, the normalised filters, the scope's fingerprint, the page size and the payload as
  sent. It is compared in constant time before the payload is decoded; every refusal is the one
  `InvalidCursorException`; the anchor row is never loaded and no cursor expires, since the scope is answered again on
  every page. A cursor is refused once the scope it was issued under changes in any way, and a denied scope is answered
  with the uniform empty page before any cursor is opened. Pages are ordered by `occurred_at` then `id`, descending,
  with the strict predicate `occurred_at < t OR (occurred_at = t AND id < i)`, led by the bound `occurred_at <= t` it
  implies, so every engine reads the time as a range of the index after the scope's equalities.
- **The read's record.** Each read is recorded under a `Querying\Enums\PackageActivity` code, the only way to mint one
  under `audit_log.`: the viewer as its actor, the category `audit`, and the scope's one tenant when it sees exactly
  one, else explicitly none. Its properties are the evidence `Querying\AccessEvidence` lists, kept exactly or the read
  is refused; the filters, the whole scope, the position a page read after and the returned `(id, hmac)` pairs, at most
  500, are its encrypted `disclosure` attachment, with a fresh 32-byte nonce, so a reader of the record sees
  fingerprints and a digest no one can reverse by trying candidates, never another tenant's ids. The fingerprints are
  HMAC-SHA256 under a key HKDF derives from the ring's signing key with the info `sinemacula/audit-log:fingerprint:v1`,
  named by `fingerprint_key`. A page's `page` is `first`, `cursor` for a cursor that gave no position, the position
  under a scope of exactly one tenant, and `next` under any other, whose record is tenantless.
- **The acknowledgement survives a rollback.** A read is refused before any query while a transaction the framework
  would not yet call committed is open on the storage connection, which the read reads, or, in outbox mode, on the
  outbox connection, whose committed row acknowledges it; the transactions manager's
  `afterCommitCallbacksShouldBeExecuted()` judges it, so the testing manager's base transaction counts as committed. The
  rule runs again just before the write. In sync mode the store must say a return is durable and keep attachments. A
  committed outbox row is acceptance, `Acknowledgement::ACCEPTED`, not delivery.
- **The read guard.** A scoped `Runtime\ReadGuard` spans the authorisation, the query, the record's delivery and its
  synchronous notification, and the notification of every package record. A terminal call entered inside it, inside the
  write guard or the failure path, or inside an event mapper, is refused before any query and reported once per window.
- **Stored versus shown.** `Querying\StoredEntry` is `RowCodec::decode()` exactly, the integrity fields included, and
  its line is the canonical encoding the entry was signed over; export and verification read it. `Querying\TrailEntry`
  is privacy-safe by construction: a concealed reason is nulled from the stored value, the properties and the context
  are projected recursively, an artifact is shown by its descriptor alone, its members never loaded, and every
  encryption envelope and an encrypted IP address is shown `encrypted` unless the scope reveals encrypted fields.
- **The reveal grant reads authenticated rows, a page at a time.** Under a revealing scope `Querying\EntryProjector`
  verifies each row's HMAC with `Integrity\RecordSigner` before any envelope reaches a reader: a row that fails, or
  whose signing key the ring does not hold, shows every envelope `unreadable`. Only the projector builds a
  `Privacy\EncryptedField`, from a verified row, and every field of the page goes to `Contracts\FieldReader::readAll()`
  in one call, answered in order and in number. The package binds `Privacy\SubjectKeyFieldReader`, which reads the
  page's keys in one statement on the writer and answers each field's typed value, `erased` or `unreadable`; how is in
  `privacy.md`. A scope without the grant never asks a reader. A revealing page's record keeps `reveal` and `fields`,
  the count of fragments shown `encrypted`, `erased`, `revealed` and `unreadable`; counts and exports never decrypt.
- **The export protocol.** Prepare a temporary file beside the target, created exclusively under `umask(0077)` and
  `0600`; read one consistent snapshot on a dedicated session, the bound first, then the chunks ascending by
  `(recorded_at, id)`; end the snapshot; journal `audit_log.trail_exported` with its canonical manifest as the `export`
  artifact, fail-closed and acknowledged; then publish the bundle and the file, by `link()` without `force`, so an
  existing target is never replaced, and by `rename()` with it, once what is there is set aside to be put back if a step
  fails. The export session's configuration resolves the connection's `url` as the database manager does, and
  verification looks the entry and its artifact up on the writer, never a lagging replica. The manifest is versioned and
  names the file and membership digests, the first and last positions, the fingerprints, the snapshot's consistency and
  the viewer.
- **Export evidence is kept.** `audit_log.trail_exported` entries are protected from retention, so `--verify` keeps
  working while the database and `app.key` live: `audit-log:prune` never deletes one, whatever its category's policy,
  and its `export` artifact goes only with its entry. The artifact's members are encrypted under `app.key`, so a key
  rotated away must stay in `app.previous_keys` for as long as an export's verification is promised.

## Success Path

1. A trail is built from `AuditLog::trail()`, narrowed by filters each validated as given, and named a viewer.
2. A terminal call checks its own arguments, then `ReadGate::enter()` lets the read in.
3. Inside the read guard the policy answers the viewer's scope for the purpose, a page's cursor is opened, and one
   statement reads the entries, for a page one row beyond its size, which is dropped before it is decoded.
4. Each row is decoded as a `StoredEntry` and projected as a `TrailEntry` through `Querying\EntryProjector`.
5. `Querying\AccessRecorder` writes the read's record through `RecordPipeline::write()` with a `Delivery\PackageWrite`:
   its `accept` check holds the evidence to what the record kept, canonically, and its `acknowledged` hand-over takes
   the finalised record once the store or the outbox has it.
6. The page, the count, the published export or the verification is returned.

## Failure / Edge Cases

- A policy that throws is recorded as `failure` with `policy_failed`, and its own exception propagates unchanged.
- A refused cursor is recorded as `denied` with `cursor_rejected`, and `InvalidCursorException` is thrown.
- A denied scope is recorded as `denied` with `no_scope` and answered as an empty trail: an empty page, `0`, an empty
  export published and journalled as denied, or a verification that finds `entry_missing`.
- A statement that fails is recorded as `failure` with `query_failed`, a row or a line that cannot be formatted with
  `format_failed`, and each is refused with `AuditReadRefusedException::failed()` naming the class alone.
- A record that cannot be written is spilled, said and reported once, and the read is refused with
  `AuditReadRefusedException::unrecorded()`; a write the store returns from without acknowledging is refused the same
  way, and nothing it found is returned.
- A field reader that throws, or answers another count or anything but readings, costs every field of the page, each
  shown as `unreadable`, reported once for the page naming its class.
- `holdingDataOf()` with a bound field encrypter other than the package's is refused with a `\LogicException` naming
  the encrypter's class, before any query, since its keys are where the key uses cannot reach.
- A file that cannot be published once journalled is removed, `audit_log.export_publish_failed` is recorded naming the
  export entry, and the export is refused.
- A row inserted into an interval the pages have already walked may be missed: occurrence order is kept, and late rows
  from queues, the outbox and imports are not revisited.
- A queued listener runs later, outside every read window, so the guard cannot refuse it: a listener that reads the
  trail must skip `audit_log.` codes itself.
- On SQLite in rollback-journal mode an export's snapshot holds back every writer's commit until it ends; in WAL mode it
  does not.
- Verification proves the row envelopes, never the completeness of the bulk members they reference, which no export
  includes; anchoring is observed later, never claimed when the export is made.

## Seams Left

- An owner-specific projection for a subject access request: the reveal grant reveals every encrypted field of every
  entry a scope sees, whoever owns it, so the other owners' fragments the selected entries hold are reviewed by the
  investigator before anything is disclosed.
- A copy for the data subject: an export is canonical evidence, its envelopes as stored, and a copy for the subject is
  built from revealed pages, never from an export.

## Implementation Anchors

- `src/Querying/AuditTrail.php`: `visibleTo()`, `cursorPaginate()`, `count()`, `export()`, `verifyExport()`;
  `src/Querying/TrailFilters.php`, `src/Querying/Viewer.php`.
- `src/Contracts/AuditAccessPolicy.php`: `scope()`; `src/Access/DenyAllPolicy.php`; `src/Access/AccessScope.php`:
  `MAX_TENANTS`, `MAX_CATEGORIES`, `MAX_ABOUT`; `src/Access/Enums/ReadPurpose.php`.
- `src/Access/ScopeCompiler.php`: `apply()`, `before()`, `after()`, `entry()`, `isEmpty()`.
- `src/Querying/ReadGate.php`: `enter()`, `confirmDurable()`; `src/Runtime/ReadGuard.php`: `during()`;
  `src/Querying/AuditReadRefusedException.php`.
- `src/Querying/TrailReader.php`: `page()`, `count()`; `src/Querying/CursorCodec.php`, `src/Querying/CursorBinding.php`,
  `src/Querying/InvalidCursorException.php`.
- `src/Querying/StoredEntry.php`, `src/Querying/EntryProjector.php`, `src/Querying/TrailEntry.php`,
  `src/Querying/TrailPage.php`; `src/Contracts/FieldReader.php`, `src/Privacy/SealedFieldReader.php`,
  `src/Privacy/Enums/FieldState.php`.
- `src/Access/AccessScope.php`: `revealingEncryptedFields()`, `revealsEncryptedFields()`; `src/Access/ScopeValues.php`;
  `src/Privacy/EncryptedField.php`: `fromEnvelope()`; `src/Privacy/SubjectKeyFieldReader.php`: `readAll()`;
  `src/Querying/FieldDisclosure.php`, `src/Querying/ProjectedPage.php`, `src/Querying/EntryColumns.php`;
  `src/Privacy/KeyStoreUse.php`.
- `src/Querying/AccessRecorder.php`: `record()`; `src/Querying/AccessEvidence.php`; `src/Delivery/PackageWrite.php`;
  `src/Querying/Enums/PackageActivity.php`: `isProtected()`; `src/Records/DisclosureManifest.php`.
- `src/Querying/Exporter.php`: `export()`; `src/Querying/ExportSnapshot.php`, `src/Querying/ExportFile.php`,
  `src/Querying/MembershipDigest.php`, `src/Querying/ExportBundle.php`, `src/Records/ExportManifest.php`,
  `src/Querying/ExportResult.php`, `src/Querying/Enums/Acknowledgement.php`.
- `src/Querying/ExportVerifier.php`: `verify()`; `src/Querying/ExportVerification.php`,
  `src/Querying/Enums/ExportFinding.php`; `src/Console/ExportCommand.php`.
- `src/Querying/Describer.php`: `describe()`; `src/Querying/ReadSettings.php`.

## Authoritative Tests

- `tests/Feature/Querying/AuditTrailTest.php` `testATerminalWithoutAViewerIsRefusedBeforeAnyQuery`,
  `testAnUnreferenceableViewerIsRefusedNotAnonymous`, `testAPageSizeOutsideTheRangeIsRefusedBeforeAnyQuery`,
  `testThereIsNoPermittedProbe`
- `tests/Unit/Querying/ViewerTest.php` `testAReferenceIsKeptAsGiven`
- `tests/Feature/Querying/TrailReaderTest.php` `testThePolicyIsGivenTheOriginalViewerAndThePurpose`,
  `testADeniedScopeMakesNoQuery`, `testTheLookAheadRowIsNeitherReturnedNorDisclosed`,
  `testAThrowingPolicyIsRecordedAsAFailureAndRethrown`, `testAPageOfBulkEntriesReadsNoArtifact`
- `tests/Feature/Access/ScopeCompilerTest.php` `testTheCompiledFormIsTenantAndCategoryAndAboutAndFiltersAndCursor`,
  `testTheCursorPredicateIsStrictAndGrouped`, `testEveryInternalOrIsGrouped`
- `tests/Unit/Access/AccessScopeTest.php` `testNoneAbsorbsEveryOperation`, `testRepeatingANarrowingIntersects`
- `tests/Feature/Querying/AccessControlTest.php` `testACallerFilterCannotEscapeAMultiTenantScope`,
  `testAPageAndACountSeeTheSameRows`, `testAGuessedTenantGivesTheSameEmptyResultAsAnUnknownOne`,
  `testOnlyAboutSelectsByActorOrSubject`, `testACursorReusedByAnotherViewerIsRefusedAndRecorded`
- `tests/Feature/Querying/TrailOrderingTest.php` `testIdenticalMicrosecondsKeepATotalOrder`
- `tests/Integration/Querying/ConcurrentPaginationTest.php` `testALateRowInAWalkedIntervalIsNotRevisited`
- `tests/Integration/Access/LikeEscapingTest.php` `testALiteralUnderscoreMatchesOnlyAnUnderscore`
- `tests/Feature/Querying/CursorCodecTest.php` `testACursorIsVersionKeyPayloadAndMac`,
  `testEachBoundFieldRefusesAnotherBinding`
- `tests/Feature/Querying/ReadGateTest.php` `testAnOpenTransactionOnTheStorageConnectionRefusesTheRead`,
  `testAnOpenTransactionOnTheOutboxConnectionRefusesAQueuedRead`,
  `testTheTestingManagersBaseTransactionCountsAsCommitted`, `testInsideAWriteWindowEntryIsRefusedAndReportedOnce`,
  `testAStoreThatKeepsNoArtifactsRefuses`, `testTheFailureModeIsNeverRead`
- `tests/Feature/Querying/AccessRecorderTest.php` `testTheRecordIsFailClosedWhateverTheFailureMode`,
  `testInOutboxModeACommittedOutboxRowIsTheAcknowledgement`, `testAFailedWriteIsSpilledReportedOnceAndRefused`,
  `testAWriteNeverAcknowledgedIsRefused`, `testATransactionOpenedByThePolicyRefusesBeforeTheWrite`,
  `testASingleTenantScopeRecordsThatTenant`, `testAnEvidenceKeyRedactedByConfigurationRefusesTheRead`
- `tests/Feature/Querying/DurableDisclosureTest.php` `testNoRowIsReturnedWhenTheReadRecordFails`,
  `testAReadInsideATransactionIsRefusedBeforeAnyQuery`
- `tests/Feature/Querying/AuditedReadsTest.php` `testADeniedReadReturnsEmptyAndIsRecordedOnce`,
  `testUnderTheFakeAReadIsAssertable`, `testReadingTheReadRecordsRecordsOnlyThatRead`
- `tests/Unit/Querying/AccessEvidenceTest.php` `testTheReadPropertiesAreExactlyThese`,
  `testTheDisclosureHoldsFiltersScopeAndReturnedPairs`
- `tests/Feature/Querying/ReadRecursionTest.php` `testASynchronousListenerReadingTheTrailIsRefusedAndReportedOnce`,
  `testAnOutboxDrainListenerReadingTheTrailIsRefused`
- `tests/Feature/Delivery/RecordedNotifierTest.php` `testAPackageRecordsListenersRunInsideTheReadGuard`
- `tests/Unit/Querying/StoredEntryTest.php` `testTheEnvelopeIsLossless`
- `tests/Feature/Querying/EntryProjectorTest.php` `testAConcealedReasonIsNulledFromTheStoredValue`,
  `testNoCiphertextReachesTheEntry`, `testAThrowingReaderIsUnreadableAndReportedOnce`,
  `testANonRevealingProjectionNeverCallsTheReader`, `testARowThatFailsItsHmacShowsEveryEnvelopeUnreadable`,
  `testTheFieldsOfAPageAreReadInOneCall`, `testAReaderAnsweringTheWrongCountCostsThePagesFields`,
  `testTheDisclosureCountsEachState`
- `tests/Unit/Privacy/EncryptedFieldTest.php` `testOnlyTheFactoryBuildsOne`
- `tests/Unit/Access/AccessScopeTest.php` `testRevealingIsOffOnEveryStartingScope`,
  `testRevealingSurvivesEveryNarrowing`, `testADeniedScopeNeverReveals`,
  `testTheGrantIsInTheNormalisedFormAndFingerprint`
- `tests/Feature/Querying/TrailReaderTest.php` `testARevealingPageRecordsItsDisclosureCounts`,
  `testACursorIssuedWithoutTheGrantIsRefusedWithIt`, `testAnOwnersPageIsOneStatementWithTheOwnerInItsFilters`
- `tests/Unit/Querying/AccessEvidenceTest.php` `testAPageRecordsItsRevealGrantAndFieldCounts`
- `tests/Feature/Querying/RevealedReadingTest.php` `testEachMarkerThroughARevealingScope`,
  `testANonRevealingScopeNeverCallsTheReader`, `testAnErasedOwnersRecordReadsErased`
- `tests/Performance/RevealedPageBudgetTest.php` `testARevealingPageAsksForItsKeysOnce`,
  `testANonRevealingPageAsksForNoKey`
- `tests/Feature/Access/ScopeCompilerTest.php` `testHoldingDataOfIsAnExistsOverKeyUsesAndTheOwnersKeys`,
  `testItStaysInsideTheScope`
- `tests/Feature/Querying/AuditTrailTest.php` `testHoldingDataOfFindsEntriesHoldingTheOwnersFragments`,
  `testACustomEncrypterThrowsNamingTheBinding`
- `tests/Integration/Querying/HoldingDataOfEnginesTest.php` `testItFindsTheOwnersEntriesOnEachEngine`,
  `testAnEntryHoldingTwoOwnersIsFoundForEach`
- `tests/Unit/Privacy/SealedFieldReaderTest.php` `testItAlwaysAnswersEncrypted`
- `tests/Feature/Querying/TrailReadingTest.php` `testTheTrailIsNotReadYourWrites`,
  `testADeletedUsersHistoryReadsAsBefore`, `testAnEncryptedPropertyReadsAsEncrypted`
- `tests/Performance/TrailQueryBudgetTest.php` `testAPageOfFiftyIsOneSelect`
- `tests/Feature/Querying/ExporterTest.php` `testAnNdjsonLineIsTheStoredEnvelopeUntouched`,
  `testTheExportIsAuthorisedForTheExportPurpose`, `testTheJournalIsWrittenAfterTheSnapshotEnds`,
  `testPrepareJournalPublishInOrder`, `testADeniedExportPublishesAnEmptyExportAndJournalsTheDenial`,
  `testInOutboxModeTheJournalIsAccepted`, `testABulkEntrysMembersAreNotExported`
- `tests/Feature/Querying/ExportSnapshotTest.php` `testAnOpenTestingTransactionIsReadInside`
- `tests/Integration/Querying/ExportSnapshotEnginesTest.php` `testARowCommittedAfterTheSnapshotIsNotRead`,
  `testAWriterCommitsWhileTheSnapshotIsOpen`
- `tests/Integration/Querying/ExportPublicationTest.php` `testAPublicationFailureRecordsPublishFailedAndThrows`,
  `testATargetCreatedAfterTheJournalIsNeverReplaced`
- `tests/Unit/Querying/ExportFileTest.php` `testTheTempFileIsCreatedExclusivelyWith0600`
- `tests/Feature/Querying/ExportVerifierTest.php` `testEachTamperingHasItsOwnFinding`,
  `testADeniedViewerSeesTheEntryMissing`, `testTheEntryIsLookedUpUnderTheScope`
- `tests/Feature/Querying/OfflineVerificationTest.php` `testTheFileAndMembershipDigestsVerifyWithoutThePackage`,
  `testTheEntryHmacVerifiesWithTheKeyAlone`, `testTheManifestIsTheOneTheSignedEntryDescribes`
- `tests/Feature/Querying/GoldenExportTest.php` `testTheGoldenVersionOneExportVerifies`
- `tests/Feature/Querying/ExportProofsTest.php` `testAPageACountAndAnExportSeeTheSameRows`
- `tests/Feature/Console/ExportCommandTest.php` `testItTakesTheViewerAsTypeAndId`,
  `testVerifyExitsOneAndListsTheFindings`
- `tests/Feature/Querying/DescriberTest.php` `testRelatedCodesDoNotCollide`
- `tests/Unit/Querying/ReadSettingsTest.php` `testTheDefaultsApplyWhenNothingIsSet`
- `tests/Feature/Querying/SubjectAccessProcedureTest.php` `testTheBlocksAreInTheGuideAsHeldHere`,
  `testTheDocumentedProcedureRuns`, `testPrincipalReferencesAreNotSelected`
- `tests/Feature/Delivery/OutcomesTableTest.php` `testRowReadSync`, `testRowReadOutbox`, `testRowReadOpenTransaction`,
  `testRowReadFailedWrite`
- `tests/Unit/Documentation/DocumentationTest.php` `testTheReadingGuideHasItsSections`,
  `testEachReadingStatementIsMade`, `testTheReadingNoteNamesTheSeamsLeft`
- `tests/Unit/Querying/Enums/PackageActivityTest.php` `testOnlyTheExportIsProtected`
- `tests/Feature/Lifecycle/PrunerTest.php` `testAProtectedExportSurvivesAndStillVerifies`

## Change Triggers

Update this note when any of the following change:

- what a terminal call refuses before any query, or what is recorded after the gate
- the scope algebra, its limits, or how a scope is compiled
- the cursor's format, its key, what it binds, or when it is refused
- the read's record: its codes, outcomes, reasons, evidence, attachment, tenant or acknowledgement
- what the gate refuses, or what the read guard spans
- what a shown entry holds, how an encrypted field is read, what the reveal grant reveals, or how a row is
  authenticated before a reader sees it
- what `holdingDataOf()` compiles to
- the export's protocol, snapshot, order, manifest, bundle or publication
- which codes retention never prunes, or what verifying an export needs kept
- the verification's chain or a finding
- the seams the read path leaves
