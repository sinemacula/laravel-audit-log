<?php

declare(strict_types = 1);

namespace Tests\Feature\Capture;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\Access\Response;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Capture\GateArguments;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Listeners\RecordGateDenial;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use Tests\Concerns\CreatesSigningInUsers;
use Tests\Concerns\SortsJsonObjectKeys;
use Tests\Fixtures\Capture\Models\SigningInUser;
use Tests\Fixtures\Capture\Models\TaggedInvoice;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for the capture of Gate denials through the provider's wiring
 * and the real Gate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordGateDenial::class)]
final class GateDenialsTest extends TestCase
{
    use CreatesSigningInUsers, SortsJsonObjectKeys;

    /** @var string The ability every test denies, unless it says otherwise. */
    private const string ABILITY = 'approve-invoice';

    /** @var string The name the invoice policy is bound under. */
    private const string POLICY = 'Tests\Fixtures\Capture\InvoicePolicy';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /** @var \Tests\Fixtures\Capture\Models\SigningInUser The user the Gate is asked about. */
    private SigningInUser $user;

    /**
     * Create the users' and invoices' tables and a user, turn Gate capture on
     * and deny the ability.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::config()->set('hashing.bcrypt.rounds', 4);

        $this->createUsersTable();
        $this->createInvoicesTable();

        $this->user     = self::newUser('alice@example.com');
        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        self::config()->set('audit-log.capture.gate.enabled', true);

        Gate::define(self::ABILITY, static fn (): bool => false);

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

    /**
     * Twenty abilities allowed write nothing.
     *
     * @return void
     */
    public function testTwentyAllowedAbilitiesGiveNoRow(): void
    {
        for ($index = 0; $index < 20; $index++) {
            Gate::define('allowed-' . $index, static fn (): bool => true);

            self::assertTrue(Gate::forUser($this->user)->allows('allowed-' . $index));
        }

        $this->assertNoEntryAndNoFailure();
    }

    /**
     * One denial writes one denied row naming the user and no subject or guard.
     *
     * @return void
     */
    public function testOneDenialGivesOneRow(): void
    {
        self::assertFalse(Gate::forUser($this->user)->allows(self::ABILITY));

        $entry = $this->onlyEntry();

        self::assertSame([CapturedActivity::GATE_DENIED->value, 'denied', null], [$entry->event, $entry->outcome, $entry->reason]);
        self::assertSame([SigningInUser::class, (string) $this->user->id, null, null], self::actorAndSubject($entry));
        self::assertNull($entry->guard);
        self::assertSame(['ability' => self::ABILITY, 'arguments' => [], 'argument_count' => 0], $entry->properties);
        self::assertSame(['security', 1], [$entry->category, $entry->event_version]);
    }

    /**
     * A denial inside a transaction that rolls back keeps its row.
     *
     * @return void
     */
    public function testADenialSurvivesARollback(): void
    {
        $this->assertThrows(function (): void {
            DB::connection(self::CONNECTION)->transaction(function (): never {
                Gate::forUser($this->user)->allows(self::ABILITY);

                throw new \DomainException('Refused.');
            });
        }, \DomainException::class);

        self::assertSame(CapturedActivity::GATE_DENIED->value, $this->onlyEntry()->event);
    }

    /**
     * With Gate capture off, its default, a denial writes nothing.
     *
     * @return void
     */
    public function testCaptureOffGivesNoRowForADenial(): void
    {
        self::config()->set('audit-log.capture.gate.enabled', false);

        self::assertFalse(Gate::forUser($this->user)->allows(self::ABILITY));

        self::config()->set('audit-log.capture.gate', []);

        self::assertTrue(Gate::forUser($this->user)->denies(self::ABILITY));

        $this->assertNoEntryAndNoFailure();
    }

    /**
     * A callback returning `null` denies and writes a denied row.
     *
     * @return void
     */
    public function testANullResultIsADenial(): void
    {
        Gate::define('undecided', static fn (): null => null);

        self::assertFalse(Gate::forUser($this->user)->allows('undecided'));

        $entry = $this->onlyEntry();

        self::assertSame([CapturedActivity::GATE_DENIED->value, 'denied'], [$entry->event, $entry->outcome]);
        self::assertSame('undecided', $entry->properties['ability'] ?? null);
    }

    /**
     * `authorize()` records its denial before it throws.
     *
     * @return void
     */
    public function testAuthorizeRecordsItsDenial(): void
    {
        try {
            Gate::forUser($this->user)->authorize(self::ABILITY);

            self::fail('Expected the ability to be denied.');
        } catch (AuthorizationException) {
            // The Gate's own answer, as the caller sees it
        }

        self::assertSame(CapturedActivity::GATE_DENIED->value, $this->onlyEntry()->event);
    }

    /**
     * `inspect()` records a listed response code as the reason, never the
     * message.
     *
     * @return void
     */
    public function testInspectRecordsItsDenial(): void
    {
        self::config()->set('audit-log.capture.gate.reason_codes', ['not_owner']);

        Gate::define('edit-invoice', static fn (): Response => Response::deny('Only the owner of invoice INV-7 may edit it.', 'not_owner'));
        Gate::define('void-invoice', static fn (): Response => Response::deny('Voiding is closed.', 'voiding_closed'));

        self::assertTrue(Gate::forUser($this->user)->inspect('edit-invoice')->denied());
        self::assertTrue(Gate::forUser($this->user)->inspect('void-invoice')->denied());

        [$listed, $unlisted] = $this->entries();

        self::assertSame(['denied', 'not_owner'], [$listed->outcome, $listed->reason]);
        self::assertSame(['denied', null], [$unlisted->outcome, $unlisted->reason]);

        foreach ([$listed, $unlisted] as $entry) {
            self::assertStringNotContainsString('INV-7', self::rowOf($entry));
            self::assertStringNotContainsString('closed.', self::rowOf($entry));
        }
    }

    /**
     * `forUser()` records that user, never the one signed in, and no guard.
     *
     * @return void
     */
    public function testForUserRecordsThatUserAndNoGuard(): void
    {
        $signedIn = self::newUser('bob@example.com');

        Auth::guard('web')->login($signedIn);

        self::assertTrue(Gate::forUser($this->user)->denies(self::ABILITY));
        self::assertTrue(Gate::denies(self::ABILITY));

        $denials = $this->denials();

        self::assertCount(2, $denials);
        self::assertSame([SigningInUser::class, (string) $this->user->id, null], [$denials[0]->actor_type, $denials[0]->actor_id, $denials[0]->guard]);
        self::assertSame([SigningInUser::class, (string) $signedIn->id, null], [$denials[1]->actor_type, $denials[1]->actor_id, $denials[1]->guard]);
    }

    /**
     * A guest's denial names no actor.
     *
     * @return void
     */
    public function testAGuestDenialHasNoActor(): void
    {
        Gate::define('view-invoice', static fn (?SigningInUser $user): bool => false);

        self::assertTrue(Gate::denies('view-invoice'));

        self::assertSame([null, null, null, null], self::actorAndSubject($this->onlyEntry()));
    }

    /**
     * Every evaluation is recorded, with no deduplication.
     *
     * @return void
     */
    public function testEveryEvaluationIsRecorded(): void
    {
        Gate::define('void-invoice', static fn (): bool => false);

        Gate::forUser($this->user)->allows(self::ABILITY);
        Gate::forUser($this->user)->allows(self::ABILITY);
        Gate::forUser($this->user)->any([self::ABILITY, 'void-invoice']);

        self::assertSame(
            [self::ABILITY, self::ABILITY, self::ABILITY, 'void-invoice'],
            array_map(static fn (AuditEntry $entry): mixed => $entry->properties['ability'] ?? null, $this->entries()),
        );
    }

    /**
     * `allowIf()` and `denyIf()` fire no event, so nothing is written.
     *
     * @return void
     */
    public function testAllowIfAndDenyIfRecordNothing(): void
    {
        foreach ([static fn (): Response => Gate::allowIf(false), static fn (): Response => Gate::denyIf(true)] as $check) {
            try {
                $check();

                self::fail('Expected the check to refuse.');
            } catch (AuthorizationException) {
                // The Gate's own answer, as the caller sees it
            }
        }

        $this->assertNoEntryAndNoFailure();
    }

    /**
     * A callback that throws ends the check before the Gate's event, so nothing
     * is written.
     *
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function testACallbackThatThrowsRecordsNothing(): void
    {
        Gate::define('broken', static fn (): never => throw new \UnexpectedValueException('The policy is broken.'));

        try {
            Gate::forUser($this->user)->allows('broken');

            self::fail('Expected the callback to throw.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('The policy is broken.', $exception->getMessage());
        }

        $this->assertNoEntryAndNoFailure();
    }

    /**
     * A policy's model argument is kept as its reference.
     *
     * @return void
     */
    public function testAPolicyArgumentIsItsReference(): void
    {
        $invoice = TaggedInvoice::query()->create(['number' => 'INV-7']);

        $this->app?->instance(self::POLICY, new class {
            /**
             * Deny every update.
             *
             * @return \Illuminate\Auth\Access\Response
             */
            public function update(): Response
            {
                return Response::deny();
            }
        });

        Gate::policy(TaggedInvoice::class, self::POLICY);

        self::assertTrue(Gate::forUser($this->user)->denies('update', [$invoice, TaggedInvoice::class, 'INV-7']));

        $entry = $this->onlyEntry();

        self::assertSame(
            self::keysSorted([
                'ability'        => 'update',
                'arguments'      => [['type' => TaggedInvoice::class, 'id' => (string) $invoice->id], TaggedInvoice::class, GateArguments::MARKER],
                'argument_count' => 3,
            ]),
            self::keysSorted($entry->properties),
        );
        self::assertNull($entry->subject_type);
        self::assertStringNotContainsString('INV-7', self::rowOf($entry));
    }

    /**
     * Only the abilities `only_abilities` selects and `except_abilities` keeps
     * are recorded.
     *
     * @return void
     */
    public function testTheSelectedAbilitiesAloneAreRecorded(): void
    {
        Gate::define('void-invoice', static fn (): bool => false);
        Gate::define('refund-invoice', static fn (): bool => false);

        self::config()->set('audit-log.capture.gate.only_abilities', [self::ABILITY, 'void-invoice']);
        self::config()->set('audit-log.capture.gate.except_abilities', ['void-invoice']);

        foreach ([self::ABILITY, 'void-invoice', 'refund-invoice'] as $ability) {
            self::assertTrue(Gate::forUser($this->user)->denies($ability));
        }

        self::assertSame(self::ABILITY, $this->onlyEntry()->properties['ability'] ?? null);
    }

    /**
     * A malformed Gate setting is a contained capture failure.
     *
     * @return void
     */
    public function testAMalformedSettingNeverReachesTheGateCheck(): void
    {
        self::config()->set('audit-log.capture.gate.enabled', 'yes');

        self::assertFalse(Gate::forUser($this->user)->allows(self::ABILITY));
        self::assertSame([], $this->entries());
        self::assertSame(
            [[RecordGateDenial::class, \InvalidArgumentException::class]],
            array_map(static fn (AuditCaptureFailed $failure): array => [$failure->mapperClass, $failure->exceptionClass], $this->failures),
        );
        self::assertCount(1, $this->reporter->reports());
    }

    /**
     * Assert no row was written and no capture failed.
     *
     * @return void
     */
    private function assertNoEntryAndNoFailure(): void
    {
        self::assertSame([], $this->entries());
        self::assertSame([], $this->failures);
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * The one row written.
     *
     * @return \SineMacula\Laravel\AuditLog\Models\AuditEntry
     */
    private function onlyEntry(): AuditEntry
    {
        $entries = $this->entries();

        self::assertCount(1, $entries);

        return $entries[0];
    }

    /**
     * The denials written, oldest first.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Models\AuditEntry>
     */
    private function denials(): array
    {
        return array_values(array_filter($this->entries(), static fn (AuditEntry $entry): bool => $entry->event === CapturedActivity::GATE_DENIED->value));
    }

    /**
     * Every row written, oldest first.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Models\AuditEntry>
     */
    private function entries(): array
    {
        return array_values(AuditEntry::query()->orderBy('recorded_at')->orderBy('id')->get()->all());
    }

    /**
     * The row's actor and subject, as type and id each.
     *
     * @param  \SineMacula\Laravel\AuditLog\Models\AuditEntry  $entry
     * @return array{0: ?string, 1: ?string, 2: ?string, 3: ?string}
     */
    private static function actorAndSubject(AuditEntry $entry): array
    {
        return [$entry->actor_type, $entry->actor_id, $entry->subject_type, $entry->subject_id];
    }

    /**
     * Every column of the row as it is stored, as one string.
     *
     * @param  \SineMacula\Laravel\AuditLog\Models\AuditEntry  $entry
     * @return string
     */
    private static function rowOf(AuditEntry $entry): string
    {
        return (string) json_encode($entry->getRawOriginal());
    }

    /**
     * The configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private static function config(): ConfigRepository
    {
        return app(ConfigRepository::class);
    }

    /**
     * Create the tagged invoices' table, dropped before the application is
     * destroyed.
     *
     * @return void
     */
    private function createInvoicesTable(): void
    {
        $schema = Schema::connection(self::CONNECTION);

        $schema->dropIfExists(TaggedInvoice::TABLE);
        $schema->create(TaggedInvoice::TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('number', 32)->nullable();
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::connection(self::CONNECTION)->dropIfExists(TaggedInvoice::TABLE);
        });
    }
}
