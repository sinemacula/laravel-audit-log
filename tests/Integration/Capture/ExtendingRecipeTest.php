<?php

declare(strict_types = 1);

namespace Tests\Integration\Capture;

use Illuminate\Auth\AuthManager;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent;
use SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent;
use Tests\Fixtures\Capture\Recipe\IdentityGuard;
use Tests\Fixtures\Capture\Recipe\IdentitySignInMapper;
use Tests\Fixtures\Capture\Recipe\UserSignedIn;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * The extending guide's recipe for recording another package's sign-ins, on
 * every engine the suite runs on: its three blocks are in the guide as this
 * test holds them, and run as written, with nothing evaluated, they record one
 * row per sign-in.
 *
 * The other package is played by fixtures: its event is
 * `Tests\Fixtures\Capture\Recipe\UserSignedIn`, aliased to the recipe's
 * `Acme\Identity\Events\UserSignedIn`; the mapper block's class is the fixture
 * `IdentitySignInMapper`, whose text from its class declaration on is the
 * block's; and its guard is the fixture `IdentityGuard`, a session guard
 * configured as `identity` whose sign-in fires both Laravel's `Login` and the
 * package's own event. The boot block's call runs while the application boots,
 * with the fixtures imported under the recipe's names, and the config block's
 * value is set.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureMappedEvent::class)]
#[CoversClass(RecordLaravelAuthEvent::class)]
final class ExtendingRecipeTest extends TestCase
{
    /** @var string The guide the recipe is in. */
    private const string GUIDE = '/docs/guides/extending.md';

    /** @var string The mapper fixture, whose class is the recipe's. */
    private const string MAPPER_FIXTURE = '/tests/Fixtures/Capture/Recipe/IdentitySignInMapper.php';

    /** @var string The class of the other package's event, as the recipe names it. */
    private const string FOREIGN_EVENT = 'Acme\Identity\Events\UserSignedIn';

    /** @var string The mapper block, as the guide shows it. */
    private const string MAPPER_BLOCK = <<<'MD'
        <!-- recipe:mapper -->

        ```php
        <?php

        namespace App\Audit;

        use Acme\Identity\Events\UserSignedIn;
        use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
        use SineMacula\Laravel\AuditLog\Records\PendingRecord;

        final readonly class IdentitySignInMapper implements EventMapper
        {
            /**
             * The sign-in, by the user who signed in and on them, correlated with the
             * attempt it completed; any other event is skipped.
             *
             * @param  object  $event
             * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
             * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
             *
             * @throws \InvalidArgumentException
             * @throws \LogicException
             */
            #[\Override]
            public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord
            {
                if (!$event instanceof UserSignedIn) {
                    return null;
                }

                return $record->event('identity.signed_in')
                    ->by($event->user)
                    ->on($event->user)
                    ->correlatedWith('identity:' . $event->attemptId);
            }
        }
        ```
        MD;

    /** @var string The boot block, as the guide shows it. */
    private const string BOOT_BLOCK = <<<'MD'
        <!-- recipe:boot -->

        ```php
        use Acme\Identity\Events\UserSignedIn;
        use App\Audit\IdentitySignInMapper;
        use SineMacula\Laravel\AuditLog\Facades\AuditLog;

        public function boot(): void
        {
            AuditLog::map(UserSignedIn::class, IdentitySignInMapper::class);
        }
        ```
        MD;

    /** @var string The config block, as the guide shows it. */
    private const string CONFIG_BLOCK = <<<'MD'
        <!-- recipe:config -->

        ```php
        'capture' => [
            'laravel' => [
                'except_guards' => ['identity'],
            ],
        ],
        ```
        MD;

    /** @var string The call the boot block makes, which this test makes while the application boots. */
    private const string BOOT_CALL = 'AuditLog::map(UserSignedIn::class, IdentitySignInMapper::class);';

    /** @var string The code the recipe's mapper records. */
    private const string CODE = 'identity.signed_in';

    /** @var string A session guard of the application's own, not excluded. */
    private const string OTHER_GUARD = 'web';

    /** @var string A correlation id as the extending guide documents it: a lower-case namespace of up to 32 characters, a colon and a value starting with a non-space. */
    private const string CORRELATION_PATTERN = '/\A[a-z][a-z0-9_-]{0,31}:\S.*\z/u';

    /** @var int How many times Laravel's `Login` was dispatched. */
    private int $logins = 0;

    /**
     * Build the other package's guard by its driver, and count Laravel's
     * `Login`.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Auth::extend(IdentityGuard::NAME, static function (Application $app, string $name, array $config): IdentityGuard {
            // Called in the auth manager's scope, where no assertion exists
            $provider = $app->make(AuthManager::class)->createUserProvider(is_string($config['provider'] ?? null) ? $config['provider'] : null)
                ?? throw new \LogicException('The identity guard has no user provider.');

            $guard = new IdentityGuard($name, $provider, $app->make(Session::class));

            $guard->setDispatcher($app->make(Dispatcher::class));

            return $guard;
        });

        Event::listen(Login::class, function (): void {
            $this->logins++;
        });
    }

    /**
     * Each block is in the guide exactly as this test holds it, and the blocks
     * are the ones this test runs: the mapper block imports the other package's
     * event by the name the fixture is aliased to, the boot block makes the
     * call this test makes, and the config block excludes the fixture guard's
     * name.
     *
     * @return void
     */
    public function testTheRecipeIsInTheGuideVerbatim(): void
    {
        $guide = self::read(self::GUIDE);

        foreach ([self::MAPPER_BLOCK, self::BOOT_BLOCK, self::CONFIG_BLOCK] as $block) {
            self::assertStringContainsString($block, $guide);
        }

        self::assertStringContainsString('use ' . self::FOREIGN_EVENT . ';', self::MAPPER_BLOCK);
        self::assertStringContainsString(self::BOOT_CALL, self::BOOT_BLOCK);
        self::assertStringContainsString('\'except_guards\' => [\'' . IdentityGuard::NAME . '\']', self::CONFIG_BLOCK);
        self::assertSame([IdentityGuard::NAME], app(ConfigRepository::class)->get('audit-log.capture.laravel.except_guards'));
    }

    /**
     * The mapper fixture's text from its class declaration to its end is the
     * mapper block's from the same line, and the other package's event the
     * recipe names is the fixture event, so what runs here is the recipe.
     *
     * @return void
     */
    public function testTheMapperFixtureIsTheRecipesClass(): void
    {
        self::assertSame(self::classOf(self::codeOf(self::MAPPER_BLOCK)), self::classOf(self::read(self::MAPPER_FIXTURE)));
        self::assertTrue(is_a(new UserSignedIn(self::user(1), 'attempt-1'), self::FOREIGN_EVENT));
    }

    /**
     * Two sign-ins on the other package's guard fire Laravel's `Login` and the
     * package's own event each, and record one row each, both the recipe's
     * code, by the user and on them: Laravel's event is left to the mapper.
     *
     * @return void
     */
    public function testTheRecipeRecordsOneRowPerSignIn(): void
    {
        $guard = self::identityGuard();

        $guard->signIn(self::user(1), 'attempt-1');
        $guard->signIn(self::user(2), 'attempt-2');

        self::assertSame(2, $this->logins);
        self::assertSame([
            [self::CODE, StubAuthUser::class, '1', StubAuthUser::class, '1', 'identity:attempt-1'],
            [self::CODE, StubAuthUser::class, '2', StubAuthUser::class, '2', 'identity:attempt-2'],
        ], self::entries());
    }

    /**
     * Without the config block, each sign-in on the other package's guard is
     * recorded twice, once from Laravel's `Login` and once by the mapper, which
     * is what the block is there to prevent.
     *
     * @return void
     */
    public function testWithoutTheConfigBlockASignInIsRecordedTwice(): void
    {
        app(ConfigRepository::class)->set('audit-log.capture.laravel.except_guards', []);

        self::identityGuard()->signIn(self::user(1), 'attempt-1');

        self::assertSame([
            [CapturedActivity::SIGNED_IN->value, StubAuthUser::class, '1', StubAuthUser::class, '1', null],
            [self::CODE, StubAuthUser::class, '1', StubAuthUser::class, '1', 'identity:attempt-1'],
        ], self::entries());
    }

    /**
     * A sign-in on a guard of the application's own, which the recipe leaves
     * alone, is still captured from Laravel's `Login`, as a sign-in.
     *
     * @return void
     */
    public function testASignInOnAnotherGuardIsStillCoreCaptured(): void
    {
        Auth::guard(self::OTHER_GUARD)->login(self::user(3));

        self::assertSame(1, $this->logins);
        self::assertSame([
            [CapturedActivity::SIGNED_IN->value, StubAuthUser::class, '3', StubAuthUser::class, '3', null],
        ], self::entries());
    }

    /**
     * The correlation id the recipe's mapper records is the documented format:
     * the guide names it, and each id stored is a lower-case namespace, a colon
     * and the attempt.
     *
     * @return void
     */
    public function testTheCorrelationIdIsTheDocumentedFormat(): void
    {
        self::assertStringContainsString('`<namespace>:<value>`', self::read(self::GUIDE));

        self::identityGuard()->signIn(self::user(1), 'b6c5f0d2-attempt');

        $ids = array_column(self::entries(), 5);

        self::assertSame(['identity:b6c5f0d2-attempt'], $ids);
        self::assertMatchesRegularExpression(self::CORRELATION_PATTERN, $ids[0]);
    }

    /**
     * Alias the fixture event to the recipe's name, keep the session in memory,
     * configure the other package's guard, set the config block's value and
     * make the boot block's call while the application boots.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        if (!class_exists(self::FOREIGN_EVENT, false)) {
            class_alias(UserSignedIn::class, self::FOREIGN_EVENT);
        }

        $config = app(ConfigRepository::class);

        $config->set('session.driver', 'array');
        $config->set('auth.guards.' . IdentityGuard::NAME, ['driver' => IdentityGuard::NAME, 'provider' => 'users']);
        $config->set('audit-log.capture.laravel.except_guards', [IdentityGuard::NAME]);

        app()->booting(static function (): void {
            AuditLog::map(UserSignedIn::class, IdentitySignInMapper::class);
        });
    }

    /**
     * The other package's guard, as the auth manager builds it.
     *
     * @return \Tests\Fixtures\Capture\Recipe\IdentityGuard
     */
    private static function identityGuard(): IdentityGuard
    {
        $guard = Auth::guard(IdentityGuard::NAME);

        self::assertInstanceOf(IdentityGuard::class, $guard);

        return $guard;
    }

    /**
     * A saved-looking user of the id, never saved.
     *
     * @param  int  $id
     * @return \Tests\Unit\Stubs\StubAuthUser
     */
    private static function user(int $id): StubAuthUser
    {
        return (new StubAuthUser)->forceFill(['id' => $id]);
    }

    /**
     * Each entry stored, as its code, actor, subject and correlation id, in the
     * order of the code and then the correlation id.
     *
     * @return list<array{0: string, 1: ?string, 2: ?string, 3: ?string, 4: ?string, 5: ?string}>
     */
    private static function entries(): array
    {
        $columns = ['event', 'actor_type', 'actor_id', 'subject_type', 'subject_id', 'correlation_id'];
        $entries = [];

        foreach (DB::connection(self::CONNECTION)->table(EntrySettings::table())->get($columns) as $row) {
            $values = array_map(static fn (string $column): ?string => is_scalar($row->{$column} ?? null) ? (string) $row->{$column} : null, $columns);

            $entries[] = [(string) $values[0], $values[1], $values[2], $values[3], $values[4], $values[5]];
        }

        usort($entries, static fn (array $one, array $other): int => [$one[0], $one[5]] <=> [$other[0], $other[5]]);

        return $entries;
    }

    /**
     * The code of a block: what its fence holds, without the marker and the
     * fence.
     *
     * @param  string  $block
     * @return string
     */
    private static function codeOf(string $block): string
    {
        self::assertSame(1, preg_match('/^```php\n(.*?)^```$/ms', $block, $matches));

        return $matches[1];
    }

    /**
     * The text of PHP source from its class declaration to its end, with its
     * trailing whitespace dropped.
     *
     * @param  string  $source
     * @return string
     */
    private static function classOf(string $source): string
    {
        self::assertSame(1, preg_match('/^final .*\z/ms', $source, $matches));

        return rtrim($matches[0]);
    }

    /**
     * The contents of a file of the repository.
     *
     * @param  string  $path
     * @return string
     */
    private static function read(string $path): string
    {
        $contents = file_get_contents(dirname(__DIR__, 3) . $path);

        self::assertIsString($contents, sprintf('%s cannot be read.', $path));

        return $contents;
    }
}
