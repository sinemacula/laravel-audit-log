# Testing Helpers

## Purpose

This note records what the package gives an application's tests: the fake store, what it can be asked and the four
assertions; which parts of the real pipeline run with the fake and what the fake does not model, a failing fake under
each mode included; and how Laravel's test helpers change what a record holds. It decides which test can use the fake
and which belongs against a real database.

## Invariants

- `AuditLog::fake()` binds a fresh `Testing\FakeAuditStore` as the application's `Contracts\AuditStore` and returns it.
  It is a real static on the facade, not a `Recorder` method, so production code names nothing of the testing helpers.
  The store is resolved for each write, so the fake is used even when the recorder was resolved first.
  `FakeAuditStore::fake(?Container)` does the same on the container given.
- `FakeAuditStore::failing(\Throwable)` binds a fake that throws the exception from every store call and holds nothing,
  and `forget()` leaves it in force. What the caller sees is the write path's, not the fake's:
  - Under `failure.mode` set to `report` the record is spilled, the failure reported and `AuditWriteFailed` dispatched,
    and `record()` returns as usual.
  - Under `throw`, or for a `failClosed()` record, it is spilled and `AuditWriteFailed` dispatched, and the caller gets
    a `Stores\AuditWriteFailedException` naming the class of the exception given, never the exception itself.
  - A `transactional()` record does the same with no spill.
  - Under `delivery.mode` set to `outbox`, `record()` writes a row and never reaches the fake. A drain that delivers the
    row then fails: it retries, and at `delivery.outbox.max_attempts` the row is failed and kept.
- The fake says it is durable and that it joins a transaction on any connection, so a `failClosed()` or
  `transactional()` record is never refused for want of a store, whichever store production binds. A refusal of a store
  that cannot honour one is tested with that store, not the fake.
- In outbox mode a record reaches the fake when it is drained. Until a test runs `audit-log:drain` the fake holds
  nothing, and `AuditRecorded` has not been dispatched.
- The fake is read through `recorded(?Closure)`, the captured records, oldest first, or those the closure accepts;
  `finalised()`, what the store received, with the time each was recorded and its integrity fields; `hasRecorded()`,
  which reads a code as `event()` reads it, so a malformed one is refused; `count()`; and `forget()`. `recorded()` and
  the assertion closures are given `AuditRecord`. The fake uses no PHPUnit and makes no query.
- `Testing\Concerns\InteractsWithAuditLog` adds four assertions, each returning `static`:
  `assertAudited($code, ?Closure)`, `assertNotAudited($code, ?Closure)`, `assertNothingAudited()` and
  `assertAuditedTimes($code, $times)`. A code is a string or a string-backed enum case, and a closure sees only records
  of the code.
- A failed assertion lists the codes stored, in order, or says none was. It never prints a property or any other value
  of a record, since a failure message is printed to a build's log.
- The fake observes successful store calls and is no transaction engine. Deferral stays in the real delivery, so an
  after-commit record arrives when its transaction commits and never when it is rolled back; but a record written by
  `immediately()` or `transactional()` stays held if the host rolls back afterwards. Rollback, savepoint and atomicity
  behaviour belongs in tests against a real database.
- With the fake bound, the definition lookup, the timing check, the contributors, deferral and finalisation all run, so
  the fake holds the finalised record the store would have received. Field rules apply at capture, so the fake holds the
  same minimised record the database store would.

## Success Path

1. A test uses the trait, binds the fake and runs the code under test:

   ```php
   use SineMacula\Laravel\AuditLog\Facades\AuditLog;
   use SineMacula\Laravel\AuditLog\Records\AuditRecord;
   use SineMacula\Laravel\AuditLog\Testing\Concerns\InteractsWithAuditLog;

   final class ApproveInvoiceTest extends TestCase
   {
       use InteractsWithAuditLog;

       public function testApprovingAnInvoiceIsAudited(): void
       {
           AuditLog::fake();

           $this->post('/invoices/42/approve');

           $this->assertAudited('invoice.approved', static fn (AuditRecord $record): bool => $record->subjectId === '42')
               ->assertAuditedTimes('invoice.approved', 1)
               ->assertNotAudited('invoice.voided');
       }
   }
   ```

2. The record passes through the pipeline, and `RecordDelivery` finalises it and gives it to the fake instead of the
   database store.
3. A test of a failure binds `FakeAuditStore::failing(new \RuntimeException('Storage is down.'))`, then asserts what its
   policy promises: under `report`, that the code carries on and `AuditWriteFailed` was dispatched, and under `throw`,
   that a `Stores\AuditWriteFailedException` reaches it.
4. Between two phases of one test, `forget()` empties the fake.

## Failure / Edge Cases

- `Event::fake()` with no class list replaces the dispatcher the frame listeners are on, so use
  `Event::fake([AuditRecorded::class])`. With no list a job enters no frame, so its record has the origin `console` and
  no job's name, and when Context is first resolved after the fake, nothing is carried into a job. A command's events
  come through the dispatcher the console kernel was built with, so they may still arrive, and a test must not rely on
  it either way.
- `withoutMiddleware()` means no HTTP frame, so a record in that request has the origin `console` and no client.
- `WithConsoleEvents` is needed for command frames, since Laravel raises command events only when it is not running unit
  tests. Without it a command enters no frame, so its record has no name, and a test expecting the origin `console`
  passes on nothing.
- A record made after `$this->get()` in the same test still sees that request, because the HTTP frame is never popped.
  Each new request replaces it and gets a new request id.
- A record made in a test's own body, with no request sent, is outside any frame: the origin `console`, with no name and
  no client.
- `transactional()` counts a `DatabaseTransactions` wrapper as an open transaction, because it asks the connection,
  whose level includes the wrapper. A record a production path would refuse with a `\LogicException` is therefore
  accepted inside the wrapper, so a test of that refusal runs without it.
- The timing check runs with the fake bound. The fake answers only whether it joins a transaction, and the check still
  reads the connection, so `transactional()` still needs a transaction open on the storage connection, or on the outbox
  connection in outbox mode.
- After-commit deferral does not count the wrapper, which Laravel's testing transactions manager leaves out: a record
  inside only the wrapper is written at once, and one inside a transaction nested in it waits for that commit.
- `AuditLog::define()` and `AuditLog::contribute()` are refused once the application has booted, as they are in
  production, and a test's body runs after that. Register inside `$app->booting()`, from `defineEnvironment()`:

  ```php
  #[\Override]
  protected function defineEnvironment($app): void
  {
      parent::defineEnvironment($app);

      $app->booting(static function ($app): void {
          $app->make(Recorder::class)->define(InvoiceActivity::class);
          $app->make(Recorder::class)->contribute(OrganisationContributor::class);
      });
  }
  ```

- Finalisation runs, so a test needs what signing needs: with no `app.key` and no `integrity.keys`, a record is refused
  with an `\InvalidArgumentException` even with the fake bound. Minimising runs too, so a record that needs a hash needs
  `redaction.key` or `app.key`, whatever signs it.
- An assertion with no fake bound fails the test, telling it to call `AuditLog::fake()`.
- A fake bound in a request under Octane belongs to that request's sandbox and does not reach the next.

## Implementation Anchors

- `src/Facades/AuditLog.php`: `fake()`.
- `src/Testing/FakeAuditStore.php`: `fake()`, `failing()`, `store()`, `recorded()`, `finalised()`, `hasRecorded()`,
  `count()`, `forget()`.
- `src/Testing/Concerns/InteractsWithAuditLog.php`: `assertAudited()`, `assertNotAudited()`, `assertNothingAudited()`,
  `assertAuditedTimes()`.
- `src/Delivery/RecordDelivery.php`: `check()`, `deliver()`; `src/Database/AfterCommit.php`.
- `src/Contracts/DurableAuditStore.php`: `isDurable()`, `participatesIn()`; `src/Delivery/OutboxDrainer.php`: `drain()`.

## Authoritative Tests

- `tests/Feature/Testing/FakeAuditStoreTest.php` `testFakeBindsAFreshFakeOnTheApplication`,
  `testFakeBindsOnTheContainerGiven`, `testFailingBindsOnTheApplication`, `testRecordedListsOldestFirst`,
  `testRecordedFiltersWithTheClosure`, `testFinalisedGivesWhatTheStoreReceived`, `testHasRecordedTakesAStringOrAnEnum`,
  `testHasRecordedRefusesAnInvalidCode`, `testCountCounts`, `testForgetForgets`, `testFailingThrowsTheExceptionGiven`,
  `testAFailingFakeHoldsNothing`, `testForgetLeavesAFailureInForce`, `testIsDurable`, `testParticipatesInAnyConnection`,
  `testUsesNoPhpUnit`, `testMakesNoQuery`
- `tests/Feature/Delivery/StoreCapabilitiesTest.php` `testTheFakeIsDurableAndJoinsAnyTransaction`
- `tests/Feature/Delivery/RecordDeliveryTest.php` `testAReportModeFailureReturnsAndNotifiesNothing`,
  `testATransactionalRecordThrowsWhateverTheMode`, `testAFailClosedRecordThrowsWhateverTheMode`,
  `testOutboxModeWritesNoEntryAndDispatchesNothing`
- `tests/Feature/Delivery/OutboxDrainerTest.php` `testDrainingStoresTheRecordAndDeletesTheRow`,
  `testTheFinalAttemptFailsTheRowAndKeepsIt`
- `tests/Feature/Testing/Concerns/InteractsWithAuditLogTest.php` `testAssertAuditedPassesWhenTheCodeWasRecorded`,
  `testAssertAuditedFailsWhenItWasNot`, `testAssertAuditedHonoursTheClosure`, `testAssertNotAuditedFailsWhenItWas`,
  `testAssertNothingAuditedFailsWithARecord`, `testAssertAuditedTimesFails`, `testEveryAssertionReturnsTheTestCase`,
  `testAFailureListsWhatWasRecorded`, `testAFailureNamesNoProperty`, `testAssertingWithoutAFakeFails`
- `tests/Feature/Facades/AuditLogTest.php` `testFakeBindsTheFakeAndReturnsIt`,
  `testFakeWorksAfterTheRecorderIsResolved`, `testRecordsReachTheFakeThroughThePipeline`,
  `testADeferredRecordIsAbsentFromTheFakeUntilCommit`, `testARolledBackRecordIsAbsentFromTheFake`
- `tests/Feature/Recording/FakeParityTest.php` `testTheFakeHoldsTheRecordTheStoreReceived`,
  `testContributorsRunWithTheFake`, `testDeferralRunsWithTheFake`,
  `testAnImmediateRecordStaysInTheFakeAfterAHostRollback`, `testFailingPropagatesThroughTheRecorder`
- `tests/Feature/Privacy/CaptureMinimisationTest.php` `testTheFakeHoldsTheMinimisedRecord`
- `tests/Feature/Recording/HttpContextTest.php` `testAWithoutMiddlewareRequestHasTheConsoleOrigin`,
  `testTwoRequestsHaveDifferentIds`
- `tests/Feature/Recording/ConsoleContextTest.php` `testACommandRecordsTheConsoleOriginAndItsName`,
  `testARecordOutsideAnyFrameIsConsole`
- `tests/Feature/Http/Middleware/EnterHttpFrameTest.php` `testTheFrameOutlivesTheResponse`
- `tests/Integration/Delivery/TestingManagerTimingTest.php` `testTheWrapperIsNotSelected`,
  `testARecordInsideOnlyTheWrapperIsWrittenAtOnce`, `testANestedTransactionDefersToItsCommit`,
  `testATransactionalRecordIsAcceptedInsideOnlyTheWrapper`
- `tests/Integration/Octane/RecorderRequestsTest.php` `testAFakeBoundInARequestDoesNotReachTheNext`
- `tests/Performance/RecorderQueryBudgetTest.php` `testTheFakeCostsNoQueries`
- `tests/Feature/AuditLogServiceProviderTest.php` `testRegistrationIsFrozenOnceBooted`

## Change Triggers

Update this note when any of the following change:

- a method of the fake or its return type
- an assertion, its arguments or what its failure prints
- what runs with the fake bound, field rules included
- what the fake models of a transaction, or what it says of itself
- what a failing fake does under a failure mode or a delivery mode
- how a frame listener is registered, or a Laravel test helper that reaches it
- how `transactional()` decides a transaction is open
- when registration is frozen
