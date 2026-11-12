<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Unit\Stubs\StubUser;

/**
 * Unit tests for the pending record's lifecycle: nothing is written without
 * `record()`, the recorder seam, single use, the snapshot it gives without
 * being used up, that no method takes a provenance, that the order of different
 * calls never matters, and that every programming error is an SPL exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingRecord::class)]
#[CoversClass(PendingSnapshot::class)]
final class PendingRecordTest extends TestCase
{
    /** @var string The reuse refusal. */
    private const string REUSED = 'A pending record is recorded once, and this one has already been recorded.';

    /**
     * Describing a record and dropping the builder never calls its recorder,
     * and the builder has no destructor that could.
     *
     * @return void
     */
    public function testNothingIsRecordedWithoutRecord(): void
    {
        $calls   = 0;
        $pending = self::fullBuilder(static function (PendingRecord $pending) use (&$calls): AuditRecord {
            $calls++;

            return self::build($pending);
        });

        unset($pending);
        gc_collect_cycles();

        self::assertSame(0, $calls);
        self::assertFalse((new \ReflectionClass(PendingRecord::class))->hasMethod('__destruct'));
    }

    /**
     * `record()` hands the builder itself to its recorder and returns what the
     * recorder returns.
     *
     * @return void
     */
    public function testRecordHandsTheBuilderToItsRecorder(): void
    {
        $received = null;
        $built    = null;
        $pending  = self::fullBuilder(static function (PendingRecord $pending) use (&$received, &$built): AuditRecord {
            $received = $pending;
            $built    = self::build($pending);

            return $built;
        });

        $record = $pending->record();

        self::assertSame($pending, $received);
        self::assertSame($built, $record);
        self::assertTrue($pending->isConsumed());
    }

    /**
     * A builder made without a recorder can be described but not recorded.
     *
     * @return void
     */
    public function testRecordWithoutARecorderIsALogicError(): void
    {
        $pending = (new PendingRecord)->event('invoice.approved');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('This pending record has no recorder; make one with `AuditLog::event()`.');

        $pending->record();
    }

    /**
     * A builder is recorded once: a second `record()` is refused before the
     * recorder runs again.
     *
     * @return void
     */
    public function testASecondRecordIsALogicError(): void
    {
        $calls   = 0;
        $pending = self::fullBuilder(static function (PendingRecord $pending) use (&$calls): AuditRecord {
            $calls++;

            return self::build($pending);
        });

        $pending->record();

        try {
            $pending->record();
            self::fail('Expected the second record to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(self::REUSED, $exception->getMessage());
        }

        self::assertSame(1, $calls);
    }

    /**
     * A builder is consumed once.
     *
     * @return void
     */
    public function testConsumingTwiceIsALogicError(): void
    {
        $pending = (new PendingRecord)->event('invoice.approved');
        $pending->consume();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::REUSED);

        $pending->consume();
    }

    /**
     * A builder with no event code cannot be consumed, and the refusal leaves
     * it usable, so the code can still be set.
     *
     * @return void
     */
    public function testConsumingWithoutAnEventCodeIsALogicError(): void
    {
        $pending = new PendingRecord;

        try {
            $pending->consume();
            self::fail('Expected a builder without a code to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('A pending record needs an event code before it is recorded; set one with `event()`.', $exception->getMessage());
        }

        self::assertFalse($pending->isConsumed());
        self::assertSame('invoice.approved', $pending->event('invoice.approved')->consume()->code?->value);
    }

    /**
     * A builder is not consumed until `consume()` is called, and then it is; a
     * snapshot does not consume it.
     *
     * @return void
     */
    public function testIsConsumed(): void
    {
        $pending = (new PendingRecord)->event('invoice.approved');

        self::assertFalse($pending->isConsumed());

        $pending->snapshot();

        self::assertFalse($pending->isConsumed());

        $pending->consume();

        self::assertTrue($pending->isConsumed());
    }

    /**
     * Consuming returns the same state a snapshot taken just before it gives.
     *
     * @return void
     */
    public function testConsumingReturnsTheFinalSnapshot(): void
    {
        $pending  = self::fullBuilder();
        $snapshot = $pending->snapshot();

        self::assertEquals($snapshot, $pending->consume());
    }

    /**
     * A snapshot of a consumed builder is refused like any other call.
     *
     * @return void
     */
    public function testASnapshotOfAConsumedBuilderIsALogicError(): void
    {
        $pending = (new PendingRecord)->event('invoice.approved');
        $pending->consume();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::REUSED);

        $pending->snapshot();
    }

    /**
     * A fresh builder's snapshot holds nothing but the default outcome: no
     * code, references, ids, payload, note, ambient value or timing.
     *
     * @return void
     */
    public function testAFreshSnapshotHoldsOnlyTheDefaults(): void
    {
        $snapshot = (new PendingRecord)->snapshot();

        self::assertSame(Outcome::SUCCESS, $snapshot->outcome);
        self::assertFalse($snapshot->failClosed);
        self::assertSame([], $snapshot->collisions);
        self::assertSame(0, $snapshot->collisionCount);
        self::assertSame([], $snapshot->contextCollisions);
        self::assertSame(0, $snapshot->contextCollisionCount);

        $absent = [
            $snapshot->code, $snapshot->subject, $snapshot->actor, $snapshot->principal, $snapshot->tenant,
            $snapshot->credentialId, $snapshot->correlationId, $snapshot->reason, $snapshot->properties,
            $snapshot->note, $snapshot->noteOwner, $snapshot->guard, $snapshot->sessionId, $snapshot->requestId,
            $snapshot->traceId, $snapshot->ip, $snapshot->userAgent, $snapshot->origin, $snapshot->context,
            $snapshot->timing, $snapshot->connection, $snapshot->identifier, $snapshot->manifest,
        ];

        self::assertSame(array_fill(0, 23, null), $absent);
    }

    /**
     * Every field of the full builder appears in its snapshot, and taking the
     * snapshot leaves the builder usable.
     *
     * @return void
     */
    public function testTheSnapshotReflectsTheBuilderWithoutConsumingIt(): void
    {
        $owner    = (new StubUser)->forceFill(['id' => 5]);
        $pending  = self::fullBuilder()->withNote('Approved after review', $owner);
        $snapshot = $pending->snapshot();

        self::assertSame('invoice.approved', $snapshot->code?->value);
        self::assertEquals(Reference::of('invoice', 'inv_0042'), $snapshot->subject);
        self::assertEquals(Reference::of('user', '42'), $snapshot->actor);
        self::assertEquals(Reference::of('team', '7'), $snapshot->principal);
        self::assertEquals(Reference::of('organisation', 'org_01'), $snapshot->tenant);
        self::assertSame('key_01', $snapshot->credentialId);
        self::assertSame('app:ticket-123', $snapshot->correlationId);
        self::assertSame(Outcome::DENIED, $snapshot->outcome);
        self::assertSame('policy', $snapshot->reason);
        self::assertSame(['amount' => '1200.00', 'currency' => 'GBP', 'lines' => [1, 2]], $snapshot->properties);
        self::assertSame('Approved after review', $snapshot->note);
        self::assertEquals(Reference::of(StubUser::class, '5'), $snapshot->noteOwner);
        self::assertSame('api', $snapshot->guard);
        self::assertSame('sess_ref_2', $snapshot->sessionId);
        self::assertSame('01932b4e-8a40-7000-8000-0000000000aa', $snapshot->requestId);
        self::assertSame('4bf92f3577b34da6a3ce929d0e0e4736', $snapshot->traceId);
        self::assertSame('198.51.100.9', $snapshot->ip);
        self::assertSame('curl/8.0', $snapshot->userAgent);
        self::assertSame(Origin::HTTP, $snapshot->origin);
        self::assertSame(['route' => 'invoices.approve', 'method' => 'POST'], $snapshot->context);
        self::assertSame(Timing::TRANSACTIONAL, $snapshot->timing);
        self::assertSame('business', $snapshot->connection);
        self::assertTrue($snapshot->failClosed);
        self::assertSame('alice@example.com', $snapshot->identifier);
        self::assertFalse($pending->isConsumed());
        self::assertSame(Outcome::SUCCESS, $pending->succeeded()->snapshot()->outcome);
    }

    /**
     * A bulk builder's manifest travels in its snapshot, the same instance, and
     * in the final snapshot that uses the builder up, and taking a snapshot
     * leaves the manifest in place.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAManifestTravelsInTheSnapshot(): void
    {
        $manifest = self::manifest();
        $pending  = (new PendingRecord)->event('invoice.bulk_approved');

        self::assertSame($pending, $pending->withManifest($manifest));
        self::assertSame($manifest, $pending->snapshot()->manifest);
        self::assertSame($manifest, $pending->snapshot()->manifest);
        self::assertSame($manifest, $pending->consume()->manifest);
    }

    /**
     * A builder has one manifest: a second is refused, even the same one, and
     * the first stays.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testASecondManifestIsRefused(): void
    {
        $manifest = self::manifest();
        $pending  = (new PendingRecord)->withManifest($manifest);

        foreach ([self::manifest(), $manifest] as $second) {
            try {
                $pending->withManifest($second);
                self::fail('Expected a second manifest to be refused.');
            } catch (\LogicException $exception) {
                self::assertSame('A bulk operation has one manifest.', $exception->getMessage());
            }
        }

        self::assertSame($manifest, $pending->snapshot()->manifest);
    }

    /**
     * A builder that has been used up takes no manifest.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAManifestOnAUsedBuilderIsRefused(): void
    {
        $pending = (new PendingRecord)->event('invoice.bulk_approved');
        $pending->consume();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::REUSED);

        $pending->withManifest(self::manifest());
    }

    /**
     * A builder made without a source of manifests cannot cover subjects, and
     * reads none of them.
     *
     * @return void
     */
    public function testABuilderWithoutASourceOfManifestsCoversNothing(): void
    {
        $reads    = new \ArrayObject;
        $subjects = (static function () use ($reads): \Generator {
            $reads->append(true);

            yield Reference::of('invoice', '1');
        })();

        try {
            (new PendingRecord)->event('invoice.voided')->covering($subjects);

            self::fail('Expected the builder to refuse.');
        } catch (\LogicException $exception) {
            self::assertSame('This builder has no source of manifests, so it cannot cover subjects.', $exception->getMessage());
        }

        self::assertCount(0, $reads);
    }

    /**
     * A builder given a source of manifests carries what it builds of the
     * subjects.
     *
     * @return void
     */
    public function testABuilderCarriesTheManifestItsSourceBuilds(): void
    {
        $manifest = self::manifest();
        $subjects = [Reference::of('invoice', '1')];
        $pending  = new PendingRecord(manifests: static function (iterable $given) use ($manifest, $subjects): Manifest {
            self::assertSame($subjects, $given);

            return $manifest;
        });

        self::assertSame($pending, $pending->event('invoice.voided')->covering($subjects));
        self::assertSame($manifest, $pending->snapshot()->manifest);
    }

    /**
     * The manifest given to a builder, and the subjects it is built from, are
     * marked sensitive: they hold the members of the bulk operation.
     *
     * @return void
     */
    public function testTheManifestIsSensitive(): void
    {
        $given    = (new \ReflectionMethod(PendingRecord::class, 'withManifest'))->getParameters()[0];
        $subjects = (new \ReflectionMethod(PendingRecord::class, 'covering'))->getParameters()[0];

        self::assertSame('manifest', $given->getName());
        self::assertCount(1, $given->getAttributes(\SensitiveParameter::class));
        self::assertSame('subjects', $subjects->getName());
        self::assertCount(1, $subjects->getAttributes(\SensitiveParameter::class));
    }

    /**
     * `forPackage()` names the activity's code, under the reserved prefix, and
     * returns the builder; the last code given wins, whichever way it was
     * given.
     *
     * @return void
     */
    public function testForPackageSetsAReservedCode(): void
    {
        $pending = new PendingRecord;

        self::assertSame($pending, $pending->forPackage(PackageActivity::TRAIL_READ));

        $package = $pending->snapshot();

        $pending->event('invoice.approved');

        $replaced = $pending->snapshot();

        $pending->forPackage(PackageActivity::EXPORT_VERIFIED);

        self::assertSame('audit_log.trail_read', $package->code?->value);
        self::assertSame('invoice.approved', $replaced->code?->value);
        self::assertSame('audit_log.export_verified', $pending->consume()->code?->value);
    }

    /**
     * `event()` still refuses a code under the reserved prefix, given as the
     * package's activity or as its value, and the builder keeps the code it
     * had.
     *
     * @return void
     */
    public function testEventStillRefusesAReservedCode(): void
    {
        $pending = (new PendingRecord)->event('invoice.approved');

        foreach ([PackageActivity::TRAIL_READ, 'audit_log.trail_read'] as $code) {
            try {
                $pending->event($code);

                self::fail('Expected the reserved code to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('The `audit_log.` prefix is reserved for the package\'s own event codes.', $exception->getMessage());
            }
        }

        self::assertSame('invoice.approved', $pending->snapshot()->code?->value);
    }

    /**
     * `identifiedAs()` gives the record the id given in place of a fresh one,
     * and refuses one that is not a lower-case UUID.
     *
     * @return void
     */
    public function testIdentifiedAsGivesTheRecordItsId(): void
    {
        $pending = (new PendingRecord)->forPackage(PackageActivity::TRAIL_READ);

        self::assertSame($pending, $pending->identifiedAs('01932b4e-9000-8000-8000-0000000000a1'));
        self::assertSame('01932b4e-9000-8000-8000-0000000000a1', $pending->snapshot()->id);
        self::assertNull((new PendingRecord)->snapshot()->id);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A pending record\'s id is a lower-case UUID.');

        $pending->identifiedAs('01932B4E-9000-8000-8000-0000000000A1');
    }

    /**
     * A builder whose record has been built refuses `forPackage()` as it
     * refuses every other mutator.
     *
     * @return void
     */
    public function testForPackageIsRefusedOnceRecorded(): void
    {
        $pending = (new PendingRecord)->forPackage(PackageActivity::TRAIL_COUNTED);

        $pending->consume();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::REUSED);

        $pending->forPackage(PackageActivity::TRAIL_READ);
    }

    /**
     * Rows of `[call]`: one call of each public mutator, the eighteen fluent
     * methods, the nine fillers, the manifest given either way, the package's
     * own code and the id of the package's own record, each with a valid
     * argument.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): void}>
     */
    public static function provideMutators(): iterable
    {
        foreach (self::calls() as $name => $call) {
            yield $name => [$call];
        }

        yield from [
            'succeeded' => [static function (PendingRecord $pending): void {
                $pending->succeeded();
            }],
            'failed' => [static function (PendingRecord $pending): void {
                $pending->failed();
            }],
            'afterCommit' => [static function (PendingRecord $pending): void {
                $pending->afterCommit();
            }],
            'afterTransaction' => [static function (PendingRecord $pending): void {
                $pending->afterTransaction();
            }],
            'immediately' => [static function (PendingRecord $pending): void {
                $pending->immediately();
            }],
            'fillActor' => [static function (PendingRecord $pending): void {
                $pending->fillActor(Reference::of('user', '1'));
            }],
            'fillPrincipal' => [static function (PendingRecord $pending): void {
                $pending->fillPrincipal(Reference::of('team', '1'));
            }],
            'fillTenant' => [static function (PendingRecord $pending): void {
                $pending->fillTenant(Reference::of('organisation', '1'));
            }],
            'withManifest' => [static function (PendingRecord $pending): void {
                $pending->withManifest(self::manifest());
            }],
            'covering' => [static function (PendingRecord $pending): void {
                $pending->covering([Reference::of('invoice', '1')]);
            }],
            'forPackage' => [static function (PendingRecord $pending): void {
                $pending->forPackage(PackageActivity::TRAIL_READ);
            }],
            'identifiedAs' => [static function (PendingRecord $pending): void {
                $pending->identifiedAs('01932b4e-9000-8000-8000-0000000000a1');
            }],
        ];
    }

    /**
     * Every public mutator of a consumed builder throws the reuse refusal.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): void  $call
     * @return void
     */
    #[DataProvider('provideMutators')]
    public function testEveryMutatorRefusesAConsumedBuilder(\Closure $call): void
    {
        $pending = (new PendingRecord)->event('invoice.approved');
        $pending->consume();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::REUSED);

        $call($pending);
    }

    /**
     * Rows of `[call]`: one call of each public mutator with an argument it
     * would refuse, or with `null` where a filler then does nothing; a mutator
     * that takes no argument, or only an origin or an activity, is called as it
     * always is.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): void}>
     */
    public static function provideRefusedArguments(): iterable
    {
        yield from [
            'event' => [static function (PendingRecord $pending): void {
                $pending->event('Invoice');
            }],
            'on' => [static function (PendingRecord $pending): void {
                $pending->on(new StubUser);
            }],
            'by' => [static function (PendingRecord $pending): void {
                $pending->by(new StubUser);
            }],
            'asPrincipal' => [static function (PendingRecord $pending): void {
                $pending->asPrincipal(new StubUser);
            }],
            'forTenant' => [static function (PendingRecord $pending): void {
                $pending->forTenant(new StubUser);
            }],
            'usingCredential' => [static function (PendingRecord $pending): void {
                $pending->usingCredential('');
            }],
            'correlatedWith' => [static function (PendingRecord $pending): void {
                $pending->correlatedWith('x');
            }],
            'withProperties' => [static function (PendingRecord $pending): void {
                $pending->withProperties(['_audit' => 1]);
            }],
            'withNote' => [static function (PendingRecord $pending): void {
                $pending->withNote('');
            }],
            'withIdentifier' => [static function (PendingRecord $pending): void {
                $pending->withIdentifier('');
            }],
            'viaGuard' => [static function (PendingRecord $pending): void {
                $pending->viaGuard("\n");
            }],
            'inSession' => [static function (PendingRecord $pending): void {
                $pending->inSession('');
            }],
            'fromClient' => [static function (PendingRecord $pending): void {
                $pending->fromClient(null, null);
            }],
            'succeeded' => [static function (PendingRecord $pending): void {
                $pending->succeeded();
            }],
            'failed' => [static function (PendingRecord $pending): void {
                $pending->failed('Bad Reason');
            }],
            'denied' => [static function (PendingRecord $pending): void {
                $pending->denied('Bad Reason');
            }],
            'afterCommit' => [static function (PendingRecord $pending): void {
                $pending->afterCommit('');
            }],
            'afterTransaction' => [static function (PendingRecord $pending): void {
                $pending->afterTransaction();
            }],
            'immediately' => [static function (PendingRecord $pending): void {
                $pending->immediately();
            }],
            'transactional' => [static function (PendingRecord $pending): void {
                $pending->transactional('');
            }],
            'failClosed' => [static function (PendingRecord $pending): void {
                $pending->failClosed();
            }],
            'fillActor' => [static function (PendingRecord $pending): void {
                $pending->fillActor(null);
            }],
            'fillPrincipal' => [static function (PendingRecord $pending): void {
                $pending->fillPrincipal(null);
            }],
            'fillTenant' => [static function (PendingRecord $pending): void {
                $pending->fillTenant(null);
            }],
            'fillGuard' => [static function (PendingRecord $pending): void {
                $pending->fillGuard("\n");
            }],
            'fillSession' => [static function (PendingRecord $pending): void {
                $pending->fillSession(null);
            }],
            'fillRequest' => [static function (PendingRecord $pending): void {
                $pending->fillRequest(null, null);
            }],
            'fillClient' => [static function (PendingRecord $pending): void {
                $pending->fillClient(null, null);
            }],
            'fillOrigin' => [static function (PendingRecord $pending): void {
                $pending->fillOrigin(Origin::HTTP);
            }],
            'fillContext' => [static function (PendingRecord $pending): void {
                $pending->fillContext(['a']);
            }],
            'withManifest' => [static function (PendingRecord $pending): void {
                $pending->withManifest(self::manifest());
            }],
            'covering' => [static function (PendingRecord $pending): void {
                $pending->covering([]);
            }],
            'forPackage' => [static function (PendingRecord $pending): void {
                $pending->forPackage(PackageActivity::TRAIL_READ);
            }],
            'identifiedAs' => [static function (PendingRecord $pending): void {
                $pending->identifiedAs('not-an-id');
            }],
        ];
    }

    /**
     * Every public mutator of a consumed builder throws the reuse refusal
     * before it looks at its argument: an argument it would refuse does not
     * turn the refusal into an `\InvalidArgumentException`, and `null` does not
     * let a filler return without it.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): void  $call
     * @return void
     */
    #[DataProvider('provideRefusedArguments')]
    public function testEveryMutatorRefusesAConsumedBuilderBeforeItsArgument(\Closure $call): void
    {
        $pending = (new PendingRecord)->event('invoice.approved');
        $pending->consume();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::REUSED);

        $call($pending);
    }

    /**
     * Each set of mutator rows covers every public method of the builder but
     * the lifecycle ones and its one read, so a new mutator without a row fails
     * here.
     *
     * @return void
     */
    public function testTheMutatorRowsCoverEveryPublicMutator(): void
    {
        $lifecycle = ['__construct', 'record', 'snapshot', 'consume', 'isConsumed', 'isActorSettled'];
        $public    = (new \ReflectionClass(PendingRecord::class))->getMethods(\ReflectionMethod::IS_PUBLIC);
        $methods   = array_map(static fn (\ReflectionMethod $method): string => $method->getName(), $public);
        $mutators  = array_values(array_diff($methods, $lifecycle));
        $rows      = array_keys(iterator_to_array(self::provideMutators()));
        $refused   = array_keys(iterator_to_array(self::provideRefusedArguments()));

        sort($mutators);
        sort($rows);
        sort($refused);

        self::assertCount(34, $mutators);
        self::assertSame($mutators, $rows);
        self::assertSame($mutators, $refused);
    }

    /**
     * No public method of the builder, its traits' included, takes a
     * provenance: the package sets it, never a caller.
     *
     * @return void
     */
    public function testNoPublicMethodAcceptsAProvenance(): void
    {
        $methods = (new \ReflectionClass(PendingRecord::class))->getMethods(\ReflectionMethod::IS_PUBLIC);

        self::assertNotEmpty($methods);

        foreach ($methods as $method) {
            foreach ($method->getParameters() as $parameter) {
                self::assertStringNotContainsString(Provenance::class, (string) $parameter->getType(), "{$method->getName()}() takes a provenance.");
            }
        }
    }

    /**
     * Rows of `[the order of the full builder's calls]`: forward, reversed,
     * outcome and timing first, and fillers first.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function providePermutations(): iterable
    {
        $forward = array_keys(self::calls());
        $first   = ['denied', 'transactional', 'failClosed'];
        $fillers = array_values(array_filter($forward, static fn (string $name): bool => str_starts_with($name, 'fill')));

        yield from [
            'forward'                  => [$forward],
            'reversed'                 => [array_reverse($forward)],
            'outcome and timing first' => [[...$first, ...array_values(array_diff($forward, $first))]],
            'fillers first'            => [[...$fillers, ...array_values(array_diff($forward, $fillers))]],
        ];
    }

    /**
     * The full builder's calls made in any of the orders give equal snapshots,
     * and equal snapshots give equal records;
     * `AuditRecordTest::testPermutedCallOrdersGiveEqualEnvelopes` checks the
     * envelope.
     *
     * @param  list<string>  $order
     * @return void
     */
    #[DataProvider('providePermutations')]
    public function testPermutedCallOrdersGiveEqualRecords(array $order): void
    {
        $calls     = self::calls();
        $reference = self::fullBuilder();
        $permuted  = new PendingRecord;

        self::assertCount(count($calls), $order);

        foreach ($order as $name) {
            $calls[$name]($permuted);
        }

        self::assertEquals($reference->snapshot(), $permuted->snapshot());
    }

    /**
     * Rows of `[call, the exception class it throws]`: programming errors of
     * every kind.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): void, 1: class-string<\Throwable>}>
     */
    public static function provideProgrammingErrors(): iterable
    {
        yield from [
            'an invalid code' => [static function (PendingRecord $pending): void {
                $pending->event('Invoice');
            }, \InvalidArgumentException::class],
            'an unsaved model' => [static function (PendingRecord $pending): void {
                $pending->on(new StubUser);
            }, \InvalidArgumentException::class],
            'a bad reason' => [static function (PendingRecord $pending): void {
                $pending->failed('Not A Code');
            }, \InvalidArgumentException::class],
            'a reserved key' => [static function (PendingRecord $pending): void {
                $pending->withProperties(['_audit' => 1]);
            }, \InvalidArgumentException::class],
            'a bad guard' => [static function (PendingRecord $pending): void {
                $pending->viaGuard('');
            }, \InvalidArgumentException::class],
            'a bad session reference' => [static function (PendingRecord $pending): void {
                $pending->inSession(str_repeat('s', 192));
            }, \InvalidArgumentException::class],
            'a bad correlation id' => [static function (PendingRecord $pending): void {
                $pending->correlatedWith('ticket-123');
            }, \InvalidArgumentException::class],
            'a conflicting timing' => [static function (PendingRecord $pending): void {
                $pending->immediately()->transactional();
            }, \LogicException::class],
            'reuse' => [static function (PendingRecord $pending): void {
                $pending->event('invoice.approved')->consume();
                $pending->succeeded();
            }, \LogicException::class],
            'recording without a code' => [static function (PendingRecord $pending): void {
                $pending->consume();
            }, \LogicException::class],
            'a second manifest' => [static function (PendingRecord $pending): void {
                $pending->withManifest(self::manifest())->withManifest(self::manifest());
            }, \LogicException::class],
        ];
    }

    /**
     * Each programming error is exactly an SPL exception, never a subclass a
     * failure policy could tell apart.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): void  $call
     * @param  class-string<\Throwable>  $expected
     * @return void
     */
    #[DataProvider('provideProgrammingErrors')]
    public function testProgrammingErrorsAreSplExceptions(\Closure $call, string $expected): void
    {
        try {
            $call(new PendingRecord);
            self::fail('Expected the call to be refused.');
        } catch (\Throwable $exception) {
            self::assertSame($expected, $exception::class);
        }
    }

    /**
     * The full builder's calls, by name, each on its own.
     *
     * @return array<string, \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): void>
     */
    private static function calls(): array
    {
        return [
            'event' => static function (PendingRecord $pending): void {
                $pending->event('invoice.approved');
            },
            'on' => static function (PendingRecord $pending): void {
                $pending->on(Reference::of('invoice', 'inv_0042'));
            },
            'by' => static function (PendingRecord $pending): void {
                $pending->by(Reference::of('user', 42));
            },
            'asPrincipal' => static function (PendingRecord $pending): void {
                $pending->asPrincipal(Reference::of('team', '7'));
            },
            'forTenant' => static function (PendingRecord $pending): void {
                $pending->forTenant(Reference::of('organisation', 'org_01'));
            },
            'viaGuard' => static function (PendingRecord $pending): void {
                $pending->viaGuard('api');
            },
            'inSession' => static function (PendingRecord $pending): void {
                $pending->inSession('sess_ref_2');
            },
            'fromClient' => static function (PendingRecord $pending): void {
                $pending->fromClient('198.51.100.9', 'curl/8.0');
            },
            'usingCredential' => static function (PendingRecord $pending): void {
                $pending->usingCredential('key_01');
            },
            'correlatedWith' => static function (PendingRecord $pending): void {
                $pending->correlatedWith('app:ticket-123');
            },
            'withProperties' => static function (PendingRecord $pending): void {
                $pending->withProperties(['amount' => '1200.00', 'currency' => 'GBP', 'lines' => [1, 2]]);
            },
            'withNote' => static function (PendingRecord $pending): void {
                $pending->withNote('Approved after review');
            },
            'withIdentifier' => static function (PendingRecord $pending): void {
                $pending->withIdentifier('alice@example.com');
            },
            'denied' => static function (PendingRecord $pending): void {
                $pending->denied('policy');
            },
            'transactional' => static function (PendingRecord $pending): void {
                $pending->transactional('business');
            },
            'failClosed' => static function (PendingRecord $pending): void {
                $pending->failClosed();
            },
            'fillGuard' => static function (PendingRecord $pending): void {
                $pending->fillGuard('web');
            },
            'fillSession' => static function (PendingRecord $pending): void {
                $pending->fillSession('sess_ref_1');
            },
            'fillRequest' => static function (PendingRecord $pending): void {
                $pending->fillRequest('01932b4e-8a40-7000-8000-0000000000aa', '4bf92f3577b34da6a3ce929d0e0e4736');
            },
            'fillClient' => static function (PendingRecord $pending): void {
                $pending->fillClient('203.0.113.7', 'Mozilla/5.0');
            },
            'fillOrigin' => static function (PendingRecord $pending): void {
                $pending->fillOrigin(Origin::HTTP);
            },
            'fillContext' => static function (PendingRecord $pending): void {
                $pending->fillContext(['route' => 'invoices.approve', 'method' => 'POST']);
            },
        ];
    }

    /**
     * The full builder, every call made in its forward order.
     *
     * @param  ?\Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\AuditRecord  $recorder
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function fullBuilder(?\Closure $recorder = null): PendingRecord
    {
        $pending = new PendingRecord($recorder);

        foreach (self::calls() as $call) {
            $call($pending);
        }

        return $pending;
    }

    /**
     * A manifest of three invoices, as a bulk operation gives a builder.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     *
     * @throws \JsonException
     */
    private static function manifest(): Manifest
    {
        return Manifest::of(RecordFactory::members(3), 3, 65536);
    }

    /**
     * A captured record for the builder's recorder to return, which uses the
     * builder up as building its own record would.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function build(PendingRecord $pending): AuditRecord
    {
        $pending->consume();

        return RecordFactory::captured();
    }
}
