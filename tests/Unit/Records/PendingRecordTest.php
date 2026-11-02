<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Records\Reference;
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
    /** @var string The id every record here is built with. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The reuse refusal. */
    private const string REUSED = 'A pending record is recorded once, and this one has already been recorded.';

    /**
     * Restore UUID generation after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Str::createUuidsNormally();

        parent::tearDown();
    }

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

        $absent = [
            $snapshot->code, $snapshot->subject, $snapshot->actor, $snapshot->principal, $snapshot->tenant,
            $snapshot->credentialId, $snapshot->correlationId, $snapshot->reason, $snapshot->properties,
            $snapshot->note, $snapshot->noteOwner, $snapshot->guard, $snapshot->sessionId, $snapshot->requestId,
            $snapshot->traceId, $snapshot->ip, $snapshot->userAgent, $snapshot->origin, $snapshot->context,
            $snapshot->timing, $snapshot->connection,
        ];

        self::assertSame(array_fill(0, 21, null), $absent);
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
        self::assertSame('web', $snapshot->guard);
        self::assertSame('sess_ref_1', $snapshot->sessionId);
        self::assertSame('01932b4e-8a40-7000-8000-0000000000aa', $snapshot->requestId);
        self::assertSame('4bf92f3577b34da6a3ce929d0e0e4736', $snapshot->traceId);
        self::assertSame('203.0.113.7', $snapshot->ip);
        self::assertSame('Mozilla/5.0', $snapshot->userAgent);
        self::assertSame(Origin::HTTP, $snapshot->origin);
        self::assertSame(['route' => 'invoices.approve', 'method' => 'POST'], $snapshot->context);
        self::assertSame(Timing::TRANSACTIONAL, $snapshot->timing);
        self::assertSame('business', $snapshot->connection);
        self::assertTrue($snapshot->failClosed);
        self::assertFalse($pending->isConsumed());
        self::assertSame(Outcome::SUCCESS, $pending->succeeded()->snapshot()->outcome);
    }

    /**
     * Rows of `[call]`: one call of each public mutator, the sixteen fluent
     * methods and the nine fillers, each with a valid argument.
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
     * that takes no argument, or only an origin, is called as it always is.
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

        self::assertCount(25, $mutators);
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
     * which hold the timing the envelope does not, and equal envelopes under
     * one id and instant.
     *
     * @param  list<string>  $order
     * @return void
     */
    #[DataProvider('providePermutations')]
    public function testPermutedCallOrdersGiveEqualRecords(array $order): void
    {
        Str::createUuidsUsing(static fn (): UuidInterface => Uuid::fromString(self::ID));

        $calls     = self::calls();
        $reference = self::fullBuilder();
        $permuted  = new PendingRecord;

        self::assertCount(count($calls), $order);

        foreach ($order as $name) {
            $calls[$name]($permuted);
        }

        self::assertEquals($reference->snapshot(), $permuted->snapshot());
        self::assertSame(self::build($reference)->toArray(), self::build($permuted)->toArray());
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
     * The full builder's calls, by name, each on its own; its note has no
     * owner, so the envelope keeps it.
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
     * The golden record's builder, every call made in its forward order.
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
     * The captured record of the builder, as the golden record is built.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function build(PendingRecord $pending): AuditRecord
    {
        $occurredAt = new \DateTimeImmutable('2026-11-01 12:34:56.789012', new \DateTimeZone('Pacific/Auckland'));

        return AuditRecord::fromPending($pending, 2, 'finance', $occurredAt, 'app-eu-1', 'eu-west-2');
    }
}
