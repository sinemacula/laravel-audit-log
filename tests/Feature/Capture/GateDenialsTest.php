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
use Tests\Fixtures\Capture\Models\SigningInUser;
use Tests\Fixtures\Capture\Models\TaggedInvoice;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for the capture of Gate denials through the provider's wiring
 * and the real Gate: no row for an allowed check, however many; one row per
 * denial evaluated, whichever way the Gate is asked (`allows()`, `authorize()`,
 * `inspect()`, `forUser()`), a `null` result included, naming the user the Gate
 * was asked for and no guard; none while capture is off; a policy's model
 * argument kept as its reference; and the paths that fire no event
 * (`allowIf()`, `denyIf()`, a callback that throws) recording nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordGateDenial::class)]
final class GateDenialsTest extends TestCase
{
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
     * Hash passwords cheaply, create the users' and the invoices' tables and a
     * user, turn Gate capture on, deny the ability, bind the reporter, and hear
     * each capture failure.
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
     * One denial writes one denied row: the Gate's code, the user as actor, no
     * subject and no guard, and the ability with no argument.
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
     * While Gate capture is off, its default, a denial writes nothing, and the
     * Gate's answer is the same.
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
     * A callback that returns `null` denies, as the Gate reads it, and so
     * writes a denied row.
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
     * `authorize()` records its denial before it throws, and the exception
     * still reaches the caller.
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
     * `inspect()` records its denial, keeping the response's code as the reason
     * when the reason codes list it, and never its message.
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
     * `forUser()` records the user the Gate was asked about, never the one
     * signed in, and no guard.
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
     * Every evaluation is recorded, with no deduplication: the same denial
     * twice is two rows, and each ability a check of any of several evaluates
     * is one.
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
     * `allowIf()` and `denyIf()` decide without evaluating an ability, so no
     * event is fired and nothing is written, though both refuse: a gap of Gate
     * capture.
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
     * A callback that throws ends the evaluation before the Gate fires its
     * event, so nothing is written and the exception reaches the caller: a gap
     * of Gate capture.
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
     * A policy's model argument is kept as its reference, a class string as
     * itself and anything else as the marker, with the full count of the
     * arguments.
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
     * Only the abilities selected are recorded: `only_abilities` limits the
     * denials recorded, and `except_abilities` removes one of them.
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
     * A malformed Gate setting is a contained failure of the capture: the Gate
     * still answers, nothing is written, and the failure is said once.
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
     * Create the users' table on the test's connection, and drop it before the
     * application is destroyed.
     *
     * @return void
     */
    private function createUsersTable(): void
    {
        $schema = Schema::connection(self::CONNECTION);

        $schema->dropIfExists(SigningInUser::TABLE);
        $schema->create(SigningInUser::TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('email', 191)->unique();
            $table->string('password', 191);
            $table->rememberToken();
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::connection(self::CONNECTION)->dropIfExists(SigningInUser::TABLE);
        });
    }

    /**
     * A saved user of the email address, with the password every user is made
     * with and the remember token given.
     *
     * @param  string  $email
     * @param  ?string  $rememberToken
     * @return \Tests\Fixtures\Capture\Models\SigningInUser
     */
    private static function newUser(string $email, #[\SensitiveParameter] ?string $rememberToken = null): SigningInUser
    {
        return SigningInUser::query()->create(['email' => $email, 'password' => SigningInUser::PASSWORD, 'remember_token' => $rememberToken]);
    }

    /**
     * Create the tagged invoices' table on the test's connection, and drop it
     * before the application is destroyed.
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

    /**
     * The value with every map's keys sorted, at any depth, so a map read back
     * from a JSON column compares the same on every engine: MySQL keeps a JSON
     * object's keys in an order of its own.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return mixed
     */
    private static function keysSorted(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }

        if (!array_is_list($value)) {
            ksort($value, SORT_STRING);
        }

        return array_map(self::keysSorted(...), $value);
    }
}
