# Provider Composition

## Purpose

This note records how an application, or a package that composes this one, changes what the package does: which
contracts it binds, which registrations it makes, in which method of its own service provider, and the order the
package's provider registers its defaults and boots. The package never looks for another package, so a binding or a
registration is the only way anything changes its behaviour, and the order is what decides whose binding wins. What
each contract must keep to is in its docblock and in the extending guide's table of extension points.

## Invariants

- The package's provider binds every default in `register()` with `singletonIf()`, `bindIf()` or `scopedIf()`, so a
  binding made before it registers is kept and one made after it replaces the default, as any later binding does. The
  order the providers are listed in therefore never decides between a default and another binding: the other binding
  always wins.
- The contracts it binds, their defaults and how long each lives:

  | Contract                      | Default                                                       | Lifetime                              |
  |-------------------------------|---------------------------------------------------------------|---------------------------------------|
  | `Contracts\Clock`             | `Support\SystemClock`                                         | One per application                   |
  | `Contracts\AuditStore`        | `Stores\DatabaseAuditStore`                                   | One per application                   |
  | `Contracts\FieldEncrypter`    | `Privacy\SubjectKeyEncrypter`                                 | Made afresh on every resolution       |
  | `Contracts\KeyWrapper`        | `Keys\LocalKeyWrapper`                                        | One per application, holding no key   |
  | `Contracts\RetentionPolicy`   | `Lifecycle\ConfiguredRetentionPolicy`                         | One per application                   |
  | `Contracts\PruneLedger`       | `Lifecycle\JournalPruneLedger`                                | One per application                   |
  | `Contracts\AuditAccessPolicy` | `Access\DenyAllPolicy`                                        | One per application                   |
  | `Contracts\FieldReader`       | `Privacy\SubjectKeyFieldReader`                               | Made afresh on every resolution       |
  | `Contracts\CheckpointAnchor`  | The anchor `integrity.anchor.driver` names, from its settings | Made afresh on every resolution       |

- The recorder, its catalogue, its contributor and mapper registries and its model watcher are one per application, and
  the recorder holds no request: the execution frames, the request identity, the report latch, the write and read
  guards, the commit queue and the captured events are scoped, so Octane and a queue worker start each request or job
  without them.
- There is no manager and no driver registry. Binding `Contracts\AuditStore` is the one seam for where records go, a
  `Stores\StackAuditStore` among the choices, and binding `Privacy\NoFieldEncrypter` is the choice never to encrypt.
- Definitions, contributors, event mappers and watched models are registrations, not bindings. They are made through
  `AuditLog::define()`, `AuditLog::contribute()`, `AuditLog::map()` and `AuditLog::watch()` from a service provider's
  `boot()`, in any provider and in either order with the package's, and each is refused with a `\LogicException` once
  the application has booted, so a long-running worker registers once.
- A contributor and a mapper are registered by class and resolved from the container for each capture, so either may
  take the application's services in its constructor and keeps no state between records.
- `AuditLog::recorder()` returns the bound `Recorder`, typed, for code that wants it without the facade's magic; it
  throws a `\LogicException` when the binding resolves to anything else. `AuditLog::fake()` is the facade's own, for
  tests, and binds a fake store in the store's place.
- Booting issues no query and reads no setting that could stop it: a malformed setting is reported by
  `audit-log:check`, never by a failed boot.

## Success Path

1. The package's provider registers: it merges `config/audit-log.php` under `audit-log` and binds each default with
   `singletonIf()`, `bindIf()` or `scopedIf()`.
2. An application's or a composing package's provider binds the contracts it replaces in its own `register()`, before
   or after the package's, and its binding is the one resolved:

   ```php
   use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
   use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
   use SineMacula\Laravel\AuditLog\Facades\AuditLog;

   final class AuditServiceProvider extends ServiceProvider
   {
       public function register(): void
       {
           $this->app->singleton(AuditAccessPolicy::class, OrganisationAuditPolicy::class);
           $this->app->singleton(RetentionPolicy::class, ContractRetentionPolicy::class);
       }

       public function boot(): void
       {
           AuditLog::define(TicketActivity::class);
           AuditLog::map(TicketEvent::class, TicketEventMapper::class);
           AuditLog::contribute(OrganisationContributor::class);
       }
   }
   ```

3. The package's provider boots, in this order: it loads its translations under the `audit-log` namespace; in the
   console, it registers its publishing tags and its commands and, once the application resolves its schedule, the
   scheduled runs; it listens for the events that track execution frames and carry context into jobs; it listens for
   Laravel's authentication events and Gate evaluations and defines the package's own codes; it prepends the middleware
   that enters an HTTP frame to the global stack; and it freezes registration once the application has booted.
4. The application's and the composing packages' `boot()` methods register their definitions, contributors, event
   mappers and watched models. All of them run before the application has booted, so each is accepted whichever
   provider boots first; the first `AuditLog::map()` adds the one listener that routes mapped events.
5. Once the application has booted, the catalogue, the contributors, the mappers and the model watcher are frozen.

## Failure / Edge Cases

- A binding made after a default has resolved still replaces it for every later resolution, as the container drops
  the resolved instance; an object that was given the default before keeps it.
- A registration made after the application has booted, from a `booted()` callback, a request or a job, throws a
  `\LogicException`. Repeating an identical registration changes nothing; a conflicting definition of a code, a
  second mapper for one class or a conflicting watch is refused, whichever provider makes it first. A definition of one
  of the package's own codes that differs from the package's is refused at boot.
- A custom `Contracts\RetentionPolicy` makes the package schedule `audit-log:prune` at `retention.schedule` whatever the
  retention days say, since only the policy knows whether anything is kept for less than forever.
- A `Contracts\PruneLedger` that does not return the records the pruner journals makes verification report every
  pruned member as missing.
- A store that does not implement `Contracts\DurableAuditStore` counts as neither durable nor joining a transaction, so
  in `sync` mode a `failClosed()` or `transactional()` record is refused while it is bound. In `outbox` mode the outbox
  gives both guarantees, so the store's capabilities are not checked. A store that does not implement
  `Contracts\AcceptsAttachments`, or answers `false`, makes `covering()` a programming error, and in `sync` mode
  every read of the trail is refused, since each read records a disclosure.
- A `Contracts\FieldEncrypter` other than `Privacy\SubjectKeyEncrypter` or `Privacy\NoFieldEncrypter`, a subclass or
  a decorator of either included, makes an erasure refuse with `unsupported_encrypter` and `holdingDataOf()` throw a
  `\LogicException`, since it keeps its keys where the package cannot see them.
- Until an application binds its own `Contracts\AuditAccessPolicy`, every viewer is denied and every read returns
  nothing, and is recorded as denied.
- A malformed anchor setting fails the resolution of the default `Contracts\CheckpointAnchor`, which stops anchoring
  alone, never sealing, and `audit-log:check` reports it.
- An application that turns off package discovery registers `AuditLogServiceProvider` itself, in any position among its
  providers.

## Implementation Anchors

- `src/AuditLogServiceProvider.php`: `register()`, `boot()`, `registerSchedule()`, `registerListeners()`,
  `registerCapture()`, `registerHttpFrame()`, `freezeRegistrationOnceBooted()`.
- `src/Facades/AuditLog.php`: `recorder()`, `fake()`; `src/Recorder.php`: `define()`, `contribute()`, `map()`,
  `watch()`.
- `src/Definitions/EventCatalogue.php`, `src/Contributors/ContributorRegistry.php`, `src/Capture/MapperRegistry.php`,
  `src/Capture/ModelWatcher.php`.
- `src/Console/IntegritySchedule.php`; `src/Integrity/Anchors/AnchorFactory.php`.
- `src/Contracts/AuditStore.php`, `src/Contracts/DurableAuditStore.php`, `src/Contracts/AcceptsAttachments.php`,
  `src/Contracts/Clock.php`, `src/Contracts/FieldEncrypter.php`, `src/Contracts/KeyWrapper.php`,
  `src/Contracts/RetentionPolicy.php`, `src/Contracts/PruneLedger.php`, `src/Contracts/AuditAccessPolicy.php`,
  `src/Contracts/FieldReader.php`, `src/Contracts/CheckpointAnchor.php`.

## Authoritative Tests

- `tests/Feature/ProviderBindingOrderTest.php` `testABindingMadeBeforeThePackageRegistersIsKept`,
  `testABindingMadeAfterThePackageRegistersReplacesTheDefault`, `testALaterBindingReplacesADefaultThatHasResolved`,
  `testAPolicyAndALedgerBoundEarlierAreKept`, `testAnEncrypterBoundEarlierIsKeptEvenUnshared`
- `tests/Feature/AuditLogServiceProviderTest.php` `testTheDefaultsAreBound`,
  `testTheEncrypterAndReaderAreBoundAfreshPerResolution`, `testTheWrapperIsBound`,
  `testTheAnchorReadsTheSettingsOnEachResolution`, `testTheRecorderIsASingleton`, `testTheRuntimeStateIsScoped`,
  `testTheCaptureStateIsScoped`, `testAnEarlierPolicyAndFieldReaderAreKept`, `testRegistrationIsFrozenOnceBooted`,
  `testMappingAndWatchingAreFrozenOnceBooted`, `testRegistrationInAProvidersBootIsAccepted`,
  `testMappingAndWatchingInAProvidersBootAreAccepted`, `testADifferentDefinitionOfAPackageCodeIsRefusedAtBoot`,
  `testAMalformedSettingDoesNotStopBoot`, `testTheHttpFrameMiddlewareIsFirstAndOnce`
- `tests/Feature/RecorderTest.php` `testAContributorIsResolvedPerCapture`, `testDefineIsRefusedAfterBoot`,
  `testContributeIsRefusedAfterBoot`, `testAnIdenticalDefinitionRepeatedIsIdempotent`,
  `testAConflictingDefinitionThrowsInEitherOrder`
- `tests/Unit/Capture/MapperRegistryTest.php` `testASecondMapperForAClassIsRefused`
- `tests/Feature/Capture/ModelWatcherTest.php` `testIdenticalWatchChangesNothing`, `testAConflictingWatchIsRefused`
- `tests/Feature/Console/IntegrityScheduleTest.php` `testACustomPolicyIsAlwaysScheduled`
- `tests/Feature/Facades/AuditLogTest.php` `testRecorderGivesTheTypedService`, `testRecorderRefusesAnotherBinding`,
  `testFakeBindsTheFakeAndReturnsIt`
- `tests/Performance/BootQueryBudgetTest.php` `testARequestThatRecordsNothingIssuesNoQueries`,
  `testBootingWithCaptureWiredCostsNoQuery`
- `tests/Unit/Documentation/DocumentationTest.php` `testEveryPublicContractIsAnExtensionPoint`,
  `testEveryFacadeMethodIsDocumented`

## Change Triggers

Update this note when any of the following change:

- a contract the provider binds, its default or its lifetime
- how a default gives way to an application's binding
- what the provider does at boot, or the order it does it in
- what is registered rather than bound, or when registration is frozen
- what the facade declares of its own
- what a custom binding turns off or refuses
