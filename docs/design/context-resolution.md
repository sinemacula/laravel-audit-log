# Context Resolution

## Purpose

This note records how a record's ambient context is found: the order of the capture pipeline, what contributors may do,
how the actor is read without ever loading a user, how execution frames decide a record's origin and client, when an
inbound request id or trace id is believed, and what travels into a queued job. A record is evidence of who did what and
where it came from, so each value's source, and what it does not claim, is fixed here.

## Invariants

- A capture runs one pipeline, in this order (`Recorder::write()`): the definition is found in `EventCatalogue`, with
  `definitions.require_registered` read for this capture; `RecordDelivery::check()` accepts the timing; the contributors
  fill the gaps, in order; a fresh snapshot is taken, because the first predates what they filled, and
  `Privacy\RecordMinimiser` minimises it under the definition; `AuditRecord::fromPending()` builds the record from what
  that leaves, its id and `occurred_at` from the `Clock` and its source from `source.id` and `source.region`;
  `RecordDelivery::deliver()` finalises it once and stores it, after commit unless the builder chose otherwise; and
  `AuditRecorded` is dispatched. A refusal of the definition or the timing consumes nothing, so it leaves the builder
  usable and runs no contributor. A failure while minimising comes after the contributors have run, but it too stores
  nothing and leaves the builder usable.
- A filled value is minimised too: what a contributor gives the context or the IP address passes through the same steps
  as what the application gave, and a secret-shaped key in a filled context is redacted (see `redaction.md`). A filled
  address that is not valid fails nothing: the record is stored with a `null` address and `$ip` in `omitted`.
- A contributor implements `Contracts\ContextContributor` and is given a `Records\Contribution`, through which it may
  fill gaps and read what it needs to decide how, but not record, choose the timing or read the properties. The defaults
  run first, as `OriginContributor`, `RequestContributor`, `ActorContributor`; the application's run after them, in the
  order they were registered.
- A contributor only fills gaps. A value given to the builder is never replaced, `by(null)` and `forTenant(null)`
  included, and the first contributor to fill a field wins. Because the defaults run first, the ambient actor beats an
  application's contributor, which fills only what the defaults left.
- No default fills a principal, a tenant or a session id unless a bound `Contracts\HeldActorReader` gives them with the
  ambient actor: otherwise each comes from an explicit value or an application's contributor. No default stores a URL,
  a path or a query string.
- The actor comes from what a guard already holds. `Contributors\AmbientActor` walks `actor.guards` in order, or the
  default guard when it is `null`, read from configuration on every capture so `Auth::shouldUse()` counts. It asks each
  guard `hasUser()`, and reads the user through `Runtime\CachedUser`, never through `user()`, which loads a user through
  the provider and dispatches `Authenticated`. The default contributors therefore make no query and dispatch no
  `Authenticated`; an application's contributor adds whatever it reads itself.
- `hasUser()` returns only a boolean, so `CachedUser` reads the guard's own `$user` with a narrowly bound closure, and
  only from a guard using Laravel's `GuardHelpers` trait, recognised by the trait and never by the guard's class or
  package. Any other guard is read only by a `Contracts\HeldActorReader` an integration binds, which reads what the
  guard has bound into a `Records\HeldActor`: the actor and any principal, tenant and session reference. A reader's
  answer beats the `GuardHelpers` reading of the same guard, and `null` leaves the guard to it. A guard neither reads,
  or a user that is neither an Eloquent model nor `Authenticatable`, gives no ambient actor: an application's
  contributor or `->by(Reference)` fills it.
- The first guard holding a user decides, and only it is given to the reader. When that guard's user cannot be read (a
  guard without the trait that no reader reads, a reader's `\InvalidArgumentException`, an unsaved model, an identifier
  that is neither a string nor an integer) there is no ambient actor, and the walk does not go on
  to a later guard, which could name a different person. To learn that such a guard holds a user the walk asks it
  `hasUser()` and nothing else, and that call must not load a user: a guard whose `hasUser()` loads one breaks the
  contract.
- The guard, principal, tenant and session go with the ambient or carried actor only: an open actor is filled with all
  of them, an actor already given as that same actor gets the principal, tenant and session but no guard, since a
  capture names its own, and `by($someoneElse)` and `by(null)` get none. Each is filled only where the record has none,
  so an explicit value, `null` included, is kept.
- A record made before the `auth` middleware has run has no actor, because no guard holds a user yet and none is loaded.
  Name the actor with `->by()`.
- `Runtime\ExecutionFrames` is a scoped stack of `ExecutionFrame`s, each an `HTTP`, `COMMAND` or `JOB` `FrameKind`. The
  innermost frame decides the origin (`http`, `console`, `queue`) and the `command` or `job` name in the context, and
  when it ends the frame beneath it comes back, so a sync-queue job or a nested Artisan call restores its caller on
  success and on failure.
- `Http\Middleware\EnterHttpFrame` starts an HTTP frame. The provider prepends it to the HTTP kernel's global stack, so
  a record in any other global middleware has its request. It is middleware and adds no route.
- The HTTP frame is the stack's base and is never popped: `enterRequest()` replaces the whole stack, and the frame lives
  until the scoped instance holding it dies. `terminating()` callbacks, `defer()` and terminable middleware therefore
  keep their request.
- `CommandStarting` enters a command frame and `CommandFinished`, which also fires when the command throws, leaves it.
  `JobProcessing` enters a job frame, and `JobProcessed`, `JobFailed` and `JobExceptionOccurred` each leave it. A frame
  is left by the identity of its owner, so leaving twice is harmless, and any inner frame an exception orphaned goes
  with it.
- The events that end a frame are listened to in a `booted()` callback, after the listeners any provider's `boot()`
  adds. `Queue::after()`, `Queue::failing()` and a `CommandFinished` listener from a `boot()` are therefore still inside
  the frame, so a record they make has the job's or the command's origin, name and carried actor.
- Outside any frame the origin is `console`, with no name and no request metadata: a provider's `boot()` and a test body
  are outside any frame. Recording never branches on `runningInConsole()`.
- Request metadata (the IP address, the user agent, the method and the route's name) comes only from an active HTTP
  frame, and only when it is innermost, so a command or a job inside a request has the request's identifiers and no
  client or route. Laravel's placeholder console request is never a frame, so it is never read. The IP address is read
  through `Request::ip()`, so the application's trusted proxies decide it, and `redaction.ip` decides what is stored of
  it.
- The request id is what Context carries, or else one already known, or else a trusted inbound id, or else a UUID v7
  from the `Clock`, generated on first use. The trace id is what Context carries, or else one already known, or else a
  trusted `traceparent`, and is never generated. Each is kept in hidden Context (`audit-log.request_id`,
  `audit-log.trace_id`) so it stays the same for the rest of the work.
- The scoped `RequestIdentity` also remembers each id it has found, because `Context::scope()` restores hidden Context
  when it ends and would drop an id first made inside it. Context comes first, so a job's hydrated ids win, and a
  remembered id is written back to Context. `EnterHttpFrame` forgets the remembered ids and the package's hidden keys
  when a request enters, and nothing else in Context; a job on a worker forgets the remembered ids when it starts, so a
  job with no envelope gets a fresh id.
- Both inbound headers are off by default. `context.trust_request_id` trusts the header `context.request_id_header`
  names, and `context.trust_traceparent` trusts `traceparent`. A header is believed only when its flag is on **and**
  `Request::isFromTrustedProxy()` is true, so `TrustProxies` must be configured for either flag to have any effect.
  `isFromTrustedProxy()` checks only the immediate peer, so the trusted edge must overwrite or validate these headers:
  otherwise it passes on whatever the client sent.
- A believed header has exactly one value and is well formed. A request id is 1 to 64 visible ASCII characters. A
  `traceparent` is the full version `00` format, `00-<32 hex trace id>-<16 hex parent id>-<2 hex flags>`, lower case,
  with neither id all zeros. Anything else falls through silently.
- No claimed id is kept: a header that is not believed is never stored, reported or printed.
- An inbound header is read from the HTTP frame anywhere on the stack, for identity only, because the id is stored once
  it is generated: reading the innermost frame alone would let a nested command's first record replace the request's
  trusted id with a generated one for the rest of the request.
- When a job is queued, `Listeners\CarryContextIntoJobs` writes on the repository `ContextDehydrating` gives it, never
  on the facade: the request id, generated now if none exists yet, the trace id, and the actor's snapshot as strings
  (`audit-log.actor_type`, `audit-log.actor_id`, `audit-log.actor_guard`, and when known `audit-log.principal_type`,
  `audit-log.principal_id`, `audit-log.tenant_type`, `audit-log.tenant_id` and `audit-log.session`). Carrying an actor
  replaces the whole envelope, so an earlier actor's context never goes on with a later one. With no ambient actor
  inside a job, the actor that job carried goes on, so chained jobs inherit it; any other snapshot left in Context is
  dropped.
- In the job the identifiers are read from the hydrated Context, and `TrackJobFrames` reads the actor's snapshot from it
  as the job starts and keeps it on the job's frame, because Laravel hydrates a nested sync job's payload into the same
  Context and leaves it there. The frame's snapshot, the innermost job's, is what a record falls back to and what goes on
  to a job dispatched next. All of it is validated as scalars: a missing, partial or malformed envelope is ignored,
  never trusted and never an error.
- The snapshot records who started the work, not current authentication. It is never resolved back into a model, and it
  stays valid after the actor is deleted.
- **Hidden Context travels in the queue payload unencrypted.** It stays out of the logs, but the actor's reference, the
  guard's name and the identifiers can be read by anything that can read the queue's storage. `ShouldBeEncrypted`
  encrypts the job's command, not this.
- Only the package's own state is ever reset: its frames, its remembered ids and its hidden keys. The rest of Context
  and the guards belong to the application and are left alone.
- Laravel's guards outlive a job on a worker, so `TrackJobFrames` notes on the frame of any job that is not a `SyncJob`
  the very user objects the guards already hold. While that frame is on the stack a guard still holding the identical
  object counts as holding nobody, both for a record and for what the job dispatches. A leftover therefore never names
  the next job: the job's carried snapshot applies, or no actor when it has none. A user the job signs in itself is a
  new object and counts, even as the same person. A sync job notes nothing, since the guards' users are its caller's.
- A readable guard user that is not a leftover beats the carried snapshot. The snapshot applies while a job frame is
  anywhere on the stack, so a command inside a job keeps it, and when the guard holding a user cannot be read.
- The recorder is stateless. The singleton `Recorder` holds only frozen registration data, the definitions and the
  contributors' class names. Contributors, runtime state, the clock, the store and the finaliser are resolved from the
  current container on every capture, so `AuditLog::fake()` works after the recorder is resolved and Octane retains no
  request object.
- `AuditLog::define()` and `AuditLog::contribute()` are called while the application boots, from a service provider's
  `boot()`, not from a `booted()` callback: the provider freezes both lists in a `booted()` callback of its own, and a
  later call throws a `\LogicException`. Under Octane, registration therefore happens once per worker.

## Success Path

1. A contributor fills what is still a gap, and a service provider's `boot()` registers it:

   ```php
   use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
   use SineMacula\Laravel\AuditLog\Records\Contribution;
   use SineMacula\Laravel\AuditLog\Records\Reference;

   final readonly class OrganisationContributor implements ContextContributor
   {
       public function __construct(private CurrentOrganisation $organisation) {}

       public function contribute(Contribution $contribution): void
       {
           $contribution->fillTenant(Reference::of('organisation', $this->organisation->id()));
       }
   }

   // In a service provider's boot()
   AuditLog::contribute(OrganisationContributor::class);
   ```

2. A request enters `EnterHttpFrame` before any other global middleware, which replaces the frames and forgets any
   earlier identity.
3. `AuditLog::record()` runs the pipeline. `OriginContributor` fills `http`; `RequestContributor` fills the request id,
   generating it on first use, any trace id, the client, the method and the route's name; `ActorContributor` fills the
   actor and guard if a guard holds a user; the application's contributors fill what is left; and all of it is minimised
   before the record is built.
4. Every other record in the request shares the request id.
5. The request queues a job, and its payload carries the request id, the trace id and the snapshot in hidden Context.
6. A worker's `JobProcessing` enters a job frame. A record in the job has the origin `queue`, the job's class in its
   context, no client, the dispatcher's request id and trace id, and the dispatcher's actor and guard.
7. The job ends, on success or on failure, and its frame goes with it, so the next job shares nothing with this one.

## Failure / Edge Cases

- An in-process sub-request through the kernel replaces the frame, because a request replaces the whole stack and is
  never popped, and it forgets the identity; neither comes back when it returns. In a test, a record made after
  `$this->get()` still sees that request (see `testing-helpers.md`).
- On the sync queue a job's `failed()` runs in its caller's frame, because `JobExceptionOccurred` comes first and leaves
  the frame; in a worker it runs before either event, in the job frame. A job that calls `$this->fail()` and carries on
  has left its frame, since `JobFailed` leaves it, so what it records next is outside the job.
- For the same reason, a listener on whichever failure event comes second is past the frame's end. On the sync queue
  that is `JobFailed`, so `Queue::failing()` runs in the caller's frame. In a worker, for a job that has failed for good,
  it is `JobExceptionOccurred`, which runs outside any frame and has no job name or carried actor; for a job that will be
  tried again it comes alone and runs inside the frame. A worker's failure is therefore audited from `Queue::failing()`,
  and `->by()` names the actor where the frame has gone.
- A listener added after the application has booted runs after the frame has ended, since the package's own listener
  is already ahead of it.
- `$this->call()` inside a command emits no command event, so its records keep the caller's name; only `Artisan::call()`
  enters a frame.
- A guard using no `GuardHelpers` cannot be read, so its user cannot be noted as a leftover. Without a reader it gives
  no ambient actor anyway, so the job's carried snapshot applies; a guard a reader reads must not keep its user from one
  job to the next on a worker.
- A setting or a guard that cannot be read as a job starts on a worker does not stop the job: no leftover is noted, and
  a record the job makes fails closed on it.
- A record or a dispatch in global middleware ahead of `TrustProxies` runs before the proxy is trusted, so the inbound
  id is not believed: it gets a generated id, kept for the rest of the request, and the request's later records share
  it. The package cannot wait for `TrustProxies` without naming that middleware.
- The method a client asks for through `_method` or a method override header on a POST is unchecked before routing, and
  a record made then reads it. Only a standard method is stored: an oversized or malformed override leaves `method` out
  of the context, and the record is still written.
- A malformed `actor.guards`, `context.trust_request_id`, `context.request_id_header` or `context.trust_traceparent`
  fails closed with an `\InvalidArgumentException` naming the key and never the value, whichever peer the request came
  from, and `audit-log:check` reports it. A flag must be a real boolean, so a truthy string never turns trust on.
- A malformed `source.id` or `source.region`, or an `app.name` that slugs to nothing when `source.id` is not set, fails
  closed the same way.
- A guard that is not configured lets `AuthManager`'s exception propagate from the record; `audit-log:check` reports it.
- `CarryContextIntoJobs` runs inside the host's `dispatch()`, so a malformed setting or a user that cannot be referred
  to never stops a job being queued: the failure is reported and the job goes without the actor. A reporter that fails
  too is ignored, and one that dispatches while it reports does not report that dispatch's failure in turn.
- A job with no envelope, or a malformed one, has no carried actor and a fresh request id.
- A request with its middleware skipped by `withoutMiddleware()` has no HTTP frame, so its record has the origin
  `console` and no client.
- An exception from a contributor propagates and nothing is written.
- A contributor or an `AuditRecorded` listener that records unconditionally recurses, and it is the application's to
  stop: the write guard covers a store and the failure path, and `delivery.md` says what it refuses.

## Package Events

| Event                                                   | Dispatched when                 | Carries                                                                        |
|---------------------------------------------------------|---------------------------------|--------------------------------------------------------------------------------|
| `SineMacula\Laravel\AuditLog\Events\AuditRecorded`      | The store has accepted a record | The record's id, code and category, no more                                    |
| `SineMacula\Laravel\AuditLog\Events\AuditWriteFailed`   | A write failed                  | The record's id and code, the store's class and the exception's class, no more |
| `SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed` | An event could not be captured  | The classes of the event, of what translated it and of the exception, no more  |

Accepted is not always durable, and `outcomes.md` says when it is. Every package event implements
`Contracts\AuditLogEvent`.

## Implementation Anchors

- `src/Recorder.php`: `write()`; `src/Privacy/RecordMinimiser.php`: `minimise()`; `src/Facades/AuditLog.php`;
  `src/AuditLogServiceProvider.php`: `registerListeners()`, `registerHttpFrame()`, `freezeRegistrationOnceBooted()`.
- `src/Contracts/ContextContributor.php`, `src/Records/Contribution.php`, `src/Contributors/ContributorRegistry.php`.
- `src/Contracts/HeldActorReader.php`, `src/Records/HeldActor.php`.
- `src/Contributors/OriginContributor.php`, `src/Contributors/RequestContributor.php`,
  `src/Contributors/ActorContributor.php`, `src/Contributors/AmbientActor.php`: `current()`, `held()`;
  `src/Runtime/CachedUser.php`: `of()`.
- `src/Runtime/ExecutionFrames.php`: `enterRequest()`, `leave()`, `request()`, `inboundRequest()`, `carriedActor()`,
  `isLeftover()`;
  `src/Runtime/ExecutionFrame.php`; `src/Runtime/Enums/FrameKind.php`: `HTTP`, `COMMAND`, `JOB`.
- `src/Http/Middleware/EnterHttpFrame.php`, `src/Listeners/TrackCommandFrames.php`, `src/Listeners/TrackJobFrames.php`.
- `src/Runtime/RequestIdentity.php`: `requestId()`, `traceId()`, `forget()`, `forgetResolved()`;
  `src/Runtime/InboundIdentifiers.php`;
  `src/Runtime/ContextSettings.php`; `config/audit-log.php`: `actor`, `context`, `source`.
- `src/Listeners/CarryContextIntoJobs.php`, `src/Runtime/CarriedContext.php`, `src/Runtime/ActorSnapshot.php`,
  `src/Runtime/ReportLatch.php`.
- `src/Events/AuditRecorded.php`, `src/Events/AuditWriteFailed.php`, `src/Events/AuditCaptureFailed.php`,
  `src/Contracts/AuditLogEvent.php`.
- `src/Runtime/WriteGuard.php`: `during()`, `isActive()`, `isFirstRefusal()`.

## Authoritative Tests

- `tests/Feature/RecorderTest.php` `testContributorsRunInOrderDefaultsFirst`, `testADefaultBeatsALaterContributor`,
  `testAnApplicationContributorFillsAGap`, `testAContributorNeverReplacesAnExplicitValue`,
  `testTheFirstContributorToFillWins`, `testAContributorIsResolvedPerCapture`, `testAThrowingContributorPropagates`,
  `testATimingRefusalRunsNoContributor`, `testHoldsOnlyRegistrationData`, `testDefineIsRefusedAfterBoot`,
  `testContributeIsRefusedAfterBoot`, `testAFakeBoundAfterTheRecorderIsResolvedIsUsed`,
  `testMinimisingSeesWhatTheContributorsFilled`, `testAMinimiserFailureFailsTheWriteAndStoresNothing`,
  `testAMinimiserFailureLeavesTheBuilderUsable`
- `tests/Feature/Privacy/CaptureMinimisationTest.php` `testAContributedContextIsRedacted`,
  `testAnIpModeAppliesToARealRequest`, `testAnInvalidFilledIpIsNotStoredAndIsDiagnosed`,
  `testAGarbageIpStoresTheRecordWithNoAddress`, `testAContributorsGarbageIpDoesNotFailTheWrite`
- `tests/Feature/AuditLogServiceProviderTest.php` `testRegistrationIsFrozenOnceBooted`,
  `testRegistrationInAProvidersBootIsAccepted`, `testTheHttpFrameMiddlewareIsFirstAndOnce`
- `tests/Feature/Recording/HttpContextTest.php`
  `testAnAuthenticatedRequestRecordsActorGuardClientRouteMethodAndRequestId`,
  `testAnUnauthenticatedRequestRecordsNoActor`, `testARecordBeforeTheAuthMiddlewareHasNoActor`,
  `testByNamesTheActorBeforeTheAuthMiddleware`, `testByNullStaysNullInAnAuthenticatedRequest`,
  `testAnExplicitActorBeatsTheAmbientOne`, `testNoUrlOrQueryStringIsStored`,
  `testASpoofedForwardedForIsIgnoredWithoutATrustedProxy`, `testAForwardedForIsUsedWithATrustedProxy`,
  `testOneRequestIdAcrossManyRecords`, `testTwoRequestsHaveDifferentIds`,
  `testARecordInAGlobalMiddlewareHasTheHttpOrigin`, `testARecordInADeferredCallbackKeepsTheRequest`,
  `testARecordInATerminableMiddlewareKeepsTheRequest`, `testATenantContributorFillsTheTenant`,
  `testNoPrincipalTenantOrSessionByDefault`, `testExplicitBeatsContributorForActorAndTenant`,
  `testRecordingDispatchesNoAuthenticatedEvent`, `testRecordingMakesNoUserQuery`,
  `testAWithoutMiddlewareRequestHasTheConsoleOrigin`, `testAMethodOverrideNeitherReachesTheRowNorStopsTheRecord`
- `tests/Feature/Recording/OutsideTheConsoleTest.php` `testARequestRecordsTheHttpOriginAndTheClient`,
  `testTheHttpFrameMiddlewareIsFirst`, `testEachListenerIsRegistered`
- `tests/Feature/Recording/ClockAndSourceTest.php` `testAFrozenClockGivesOccurredAt`, `testTheIdEmbedsTheClockTime`,
  `testTheSourceDefaultsToASlugOfTheApplicationName`, `testAConfiguredSourceIsStored`, `testAnEmptySlugFailsClosed`
- `tests/Feature/Recording/TrustedHeadersTest.php` `testHeadersAreIgnoredWithoutATrustedProxy`,
  `testHeadersAreIgnoredWithTheFlagOff`, `testHeadersAreUsedWithBoth`, `testEachFlagTrustsOnlyItsOwnHeader`,
  `testAConfiguredRequestIdHeaderIsUsed`, `testEachMalformedRequestIdIsReplacedByAGeneratedOne`,
  `testEachMalformedTraceparentIsIgnored`, `testNoClaimedIdIsKept`, `testAMalformedHeaderIsNeverReported`,
  `testARepeatedHeaderIsNotBelieved`, `testAMalformedFlagFailsClosedAndPrintsNoHeader`,
  `testARecordBeforeTrustProxiesKeepsAGeneratedId`
- `tests/Feature/Recording/ConsoleContextTest.php` `testACommandRecordsTheConsoleOriginAndItsName`,
  `testANestedArtisanCallRestoresItsCaller`, `testAFailingNestedArtisanCallRestoresItsCaller`,
  `testACommandInARequestRestoresTheRequest`, `testAFailingCommandInARequestRestoresTheRequest`,
  `testACommandInARequestKeepsItsTrustedRequestId`, `testThisCallKeepsTheCallersName`,
  `testThePlaceholderRequestFillsNoClientOrRoute`, `testARecordOutsideAnyFrameIsConsole`,
  `testNoBranchOnRunningInConsole`, `testAListenerOnCommandFinishedRunsInTheCommandFrame`
- `tests/Feature/Recording/SyncJobContextTest.php`
  `testASyncJobRecordsQueueTheJobClassAndTheDispatchersRequestIdAndActor`, `testASyncJobRestoresTheRequestOnSuccess`,
  `testAFailingSyncJobRestoresTheRequest`, `testASyncJobRestoresACommandOnSuccess`,
  `testAFailingSyncJobRestoresACommand`, `testANestedSyncJobRestoresTheOuterJob`, `testAJobFillsNoClient`,
  `testDispatchingBeforeTheFirstRecordCarriesTheRequestId`, `testTheFailedHookOnTheSyncConnectionRunsInTheCallersFrame`,
  `testASignedOutCallerSendsNoActorAfterAnEarlierSyncJob`, `testARouteOuterJobAndInnerJobEachGetTheirFrameBack`,
  `testANestedSyncJobDoesNotReplaceTheOuterJobsCarriedActor`, `testWhatAnOuterJobSendsOnCarriesItsOwnActor`,
  `testAListenerOnJobProcessedRunsInTheJobFrame`, `testListenersOnAFailedSyncJobRunEitherSideOfTheFramesEnd`
- `tests/Integration/Queue/WorkerContextTest.php` `testAJobRecordsTheDispatchersRequestIdAndActor`,
  `testTheTraceIdTravels`, `testAJobKeepsTheActorAfterItIsDeleted`, `testTheCarriedActorIsNeverResolved`,
  `testTwoJobsInOneWorkerShareNoState`, `testAJobWithNoEnvelopeHasNoActorAndAFreshRequestId`,
  `testEachMalformedEnvelopeIsIgnored`, `testAChainedJobKeepsTheDispatchersIdentity`,
  `testAFailingJobLeavesNoFrameForTheNext`, `testTheFailedHookInAWorkerRunsInTheJobFrame`,
  `testForgettingScopedInstancesBetweenJobsLeavesNoFrame`, `testOnlyThePackagesStateIsReset`,
  `testTheHiddenEnvelopeIsInThePayloadUnencrypted`, `testAGuardAJobLeavesSignedInDoesNotNameTheNextJob`,
  `testAGuardAJobLeavesSignedInGivesAJobWithNoSnapshotNoActor`,
  `testAGuardAJobLeavesSignedInIsNotCarriedOntoWhatTheNextJobDispatches`, `testAUserAJobSignsInItselfCounts`,
  `testANestedSyncJobDoesNotReplaceTheOuterJobsCarriedActor`,
  `testAJobWithNoEnvelopeAfterOneWithAnEnvelopeHasAFreshRequestId`,
  `testListenersOnAJobThatFailsForGoodRunEitherSideOfTheFramesEnd`,
  `testARecordAfterAJobFailsItselfIsOutsideTheJobFrame`
- `tests/Integration/Octane/RecorderRequestsTest.php`
  `testARecorderResolvedAtBootServesTwoRequestsWithDifferentUsersAndHeaders`,
  `testAGuestRequestAfterAUsersCarriesNoActor`, `testEachRequestHasItsOwnRequestId`,
  `testATrustedHeaderInOneRequestDoesNotReachTheNext`, `testOriginAndContextOfOneRequestDoNotReachTheNext`,
  `testACommandInARequestLeavesNoFrameForTheNext`, `testAFailingSyncJobInARequestLeavesNoFrameForTheNext`,
  `testTheCarriedActorOfASyncJobDoesNotReachTheNext`, `testTheRecorderRetainsNoRequestObject`,
  `testTheListenersUseTheRequestsContainer`
- `tests/Integration/Octane/RegistrationRequestsTest.php` `testDefineInARequestIsRefused`,
  `testContributeInARequestIsRefused`, `testTheListenersAreRegisteredOncePerWorker`
- `tests/Performance/RecorderQueryBudgetTest.php` `testResolvingTheContextCostsNoQueries`,
  `testASessionHoldingAUserIdCostsNoQueries`, `testTheBudgetExcludesAQueryingContributor`,
  `testMakingAJobsPayloadCostsNoQueries`, `testASyncJobCostsOnlyItsOwnInsert`, `testACommandCostsOnlyItsOwnInsert`,
  `testAJobStartingOnAWorkerCostsNoQueries`
- `tests/Unit/Runtime/ExecutionFramesTest.php` `testOutsideAnyFrameTheOriginIsConsole`, `testEachFrameDecidesTheOrigin`,
  `testTheInnermostFrameDecides`, `testLeavingAJobTwiceIsHarmless`, `testLeavingPopsThroughAnOrphanedInnerFrame`,
  `testARequestReplacesTheStack`, `testRequestIsOnlyTheInnermostFrames`,
  `testInboundRequestIsFoundBeneathACommandOrAJob`
- `tests/Unit/Runtime/CachedUserTest.php` `testReadsTheUserAGuardHolds`, `testAGuardHoldingNoUserGivesNone`,
  `testNeverCallsUser`, `testNeverAsksTheProvider`, `testAGuardWithoutTheTraitGivesNone`,
  `testASubclassOfAGuardWithTheTraitIsRead`
- `tests/Unit/Runtime/CarriedContextTest.php` `testCarriesScalarsOnly`, `testEachMalformedEnvelopeIsIgnored`,
  `testAnEnvelopeIsNeverResolved`, `testTheRestOfContextIsLeftAlone`, `testReadsTheCarriedContextBack`,
  `testCarryingReplacesTheWholeEnvelope`
- `tests/Unit/Records/HeldActorTest.php` `testRefusesASessionARecordCouldNotStore`
- `tests/Unit/Runtime/InboundIdentifiersTest.php` `testIgnoresEachMalformedRequestId`,
  `testIgnoresEachMalformedTraceparent`
- `tests/Unit/Runtime/ContextSettingsTest.php` `testRefusesEachMalformedGuardList`,
  `testRefusesAnythingButABooleanForEachFlag`, `testRefusesEachMalformedHeaderName`, `testNoMessageHoldsTheValue`
- `tests/Unit/Architecture/PackageBoundaryTest.php` `testNoClassOutsideTheProviderAsksWhetherItRunsInTheConsole`,
  `testNoClassDeclaresAStaticProperty`, `testNoClassCallsAGuardsUser`
- `tests/Feature/Contributors/AmbientActorTest.php` `testGuardsAreCheckedInOrder`, `testTheFirstGuardHoldingAUserWins`,
  `testAnUnreadableFirstGuardLeavesTheActorNull`, `testAForeignGuardGivesNoActor`,
  `testAForeignGuardIsAskedOnlyHasUser`, `testAUserThatIsNeitherModelNorAuthenticatableGivesNoActor`,
  `testShouldUseChangesTheDefault`, `testAnUnconfiguredGuardPropagates`, `testAUserLeftOnAGuardIsNoActor`,
  `testAUserLeftOnAGuardFallsThroughToTheNextGuard`, `testAUserSignedInSinceCounts`, `testABoundReaderReadsAForeignGuard`,
  `testAReaderIsAskedOnlyAboutTheFirstGuardHoldingAUser`, `testAReaderThatReadsNothingFallsBackToGuardHelpers`,
  `testAReadersActorBeatsGuardHelpers`, `testAReaderThatRefusesGivesNoActor`
- `tests/Feature/Contributors/ActorContributorTest.php` `testAnExplicitActorIsKeptAndFillsNoGuard`,
  `testAnExplicitNullStaysNullAndFillsNoGuard`, `testAJobFallsBackToTheCarriedActor`,
  `testAnUnreadableGuardInAJobFallsBackToTheCarriedActor`, `testACommandInsideAJobKeepsTheCarriedActor`,
  `testACarriedActorIsIgnoredOutsideAJob`, `testTheAmbientActorBeatsTheCarriedOne`,
  `testTheFramesActorBeatsWhatASyncJobLeftInContext`, `testALeftoverGuardUserDoesNotBeatTheCarriedActor`,
  `testFillsTheReadActorWithItsContext`, `testAnActorSettledToTheAmbientOneGetsItsContext`,
  `testAnActorSettledToSomeoneElseGetsNoContext`, `testAJobFillsTheCarriedActorsContext`
- `tests/Feature/Contributors/RequestContributorTest.php` `testNoUrlPathOrQueryStringIsFilled`,
  `testACommandFrameFillsIdsAndNoClient`, `testThePlaceholderConsoleRequestIsNeverRead`,
  `testEachStandardMethodIsFilled`, `testAnOverrideThatIsNoStandardMethodIsLeftOut`
- `tests/Feature/Runtime/RequestIdentityTest.php` `testIsLazy`, `testACarriedIdBeatsATrustedHeader`,
  `testTheHeaderIsIgnoredWithNoProxyConfigured`, `testAHeaderBeneathACommandIsStillFound`,
  `testNoHeaderIsReadOutsideAnHttpFrame`, `testForgetRemovesOnlyThePackagesKeys`,
  `testAMalformedTrustSettingIsRefusedFromAnyPeer`, `testAnIdFirstMadeInsideAContextScopeOutlivesIt`,
  `testContextBeatsARememberedId`
- `tests/Feature/Http/Middleware/EnterHttpFrameTest.php` `testReplacesAnyEarlierFrames`,
  `testForgetsTheIdentityOfAnEarlierRequest`, `testLeavesTheRestOfContextAlone`, `testTheFrameOutlivesTheResponse`
- `tests/Feature/Listeners/CarryContextIntoJobsTest.php` `testWritesOnTheRepositoryItIsGiven`,
  `testDispatchingBeforeTheFirstRecordCarriesAGeneratedId`, `testCarriesTheActorAsScalars`,
  `testALeftBehindEnvelopeIsForgottenOutsideAJob`, `testACarriedEnvelopeIsKeptInsideAJob`,
  `testAMalformedSettingNeverStopsADispatch`, `testAnUnreferenceableUserNeverStopsADispatch`,
  `testAThrowingReporterNeverStopsADispatch`, `testAHandlerThatDispatchesFromItsReportDoesNotRecurse`,
  `testTheFramesActorReplacesWhatASyncJobLeftInContext`, `testALeftoverGuardUserIsNotCarried`
- `tests/Feature/Listeners/TrackJobFramesTest.php` `testEachEndingEventLeavesIt`, `testBothFailureEventsLeaveOnlyOnce`,
  `testContextIsLeftAlone`, `testTheGuardsAreLeftAlone`, `testTheFrameKeepsTheCarriedActor`,
  `testAJobOnAWorkerNotesTheUsersItFinds`, `testASyncJobNotesNoUser`, `testAMalformedSettingDoesNotStopAJobOnAWorker`
- `tests/Unit/Runtime/ReportLatchTest.php` `testSkipsAReportFromInsideAReport`, `testLetsGoWhenTheReportThrows`
- `tests/Unit/Runtime/WriteGuardTest.php` `testNestedWorkKeepsItActiveUntilTheOutermostEnds`,
  `testReleasesWhenTheWorkThrows`, `testTheFirstRefusalIsTheOnlyFirst`, `testNestedEndsDoNotClearTheRefusal`
- `tests/Unit/Events/AuditWriteFailedTest.php` `testCarriesTheFourFieldsAndNothingElse`, `testIsAPackageEvent`
- `tests/Unit/Events/AuditCaptureFailedTest.php` `testItCarriesOnlyClassNames`, `testItIsAPackageEvent`
- `tests/Feature/Listeners/TrackCommandFramesTest.php` `testCommandStartingEntersAFrameWithItsName`,
  `testCommandFinishedLeavesIt`
- `tests/Unit/Documentation/DocumentationTest.php` `testTheContextNoteStatesTheProxyPrerequisite`,
  `testTheContextNoteStatesThatHiddenContextIsNotEncrypted`, `testEveryEventIsInTheEventsTable`

## Change Triggers

Update this note when any of the following change:

- the order of the capture pipeline
- a default contributor, its order or what it fills
- how the actor is read, which guards can be read or what a guard is asked
- the frame kinds, what enters or leaves a frame, or which frame decides
- where request metadata comes from
- how a request id or a trace id is found, generated or stored
- what makes an inbound header believed, or its format
- the hidden keys, or what travels into a job
- what the package resets between requests or jobs
- what the recorder holds, or when registration is frozen
- a package event, or what one carries
