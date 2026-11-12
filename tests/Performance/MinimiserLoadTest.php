<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Privacy\FieldPolicy;
use SineMacula\Laravel\AuditLog\Privacy\KeyCeiling;
use SineMacula\Laravel\AuditLog\Privacy\KeyTokenizer;
use SineMacula\Laravel\AuditLog\Privacy\Minimised;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\RedactionSettings;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Privacy\ThrowingFieldEncrypter;

/**
 * Load budget for the minimiser: a payload of any size leaves a record within
 * its byte budgets, with only masked paths in its diagnostics, in bounded
 * memory and time.
 *
 * The time bound is generous, catching a pass that is not linear, and is not
 * asserted under Xdebug coverage. No coverage is claimed, since mutants these
 * slow tests cover would be skipped as timeouts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class MinimiserLoadTest extends PerformanceContractTestCase
{
    /** @var string The code every payload is recorded under. */
    private const string CODE = 'invoice.approved';

    /** @var string The id of the entry every capture here is minimised as. */
    private const string ENTRY_ID = '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e';

    /** @var string The memory limit the tests run under. */
    private const string MEMORY_LIMIT = '512M';

    /** @var int The most a capture's peak memory may grow by, in bytes: 128 MiB. */
    private const int MAX_MEMORY_GROWTH = 134217728;

    /** @var int Most CPU time a capture may use, in nanoseconds: far above linear work and far below quadratic. */
    private const int MAX_NANOSECONDS = 30000000000;

    /** @var int How many bytes a ten-megabyte payload holds. */
    private const int TEN_MEGABYTES = 10485760;

    /** @var int How many elements a long list holds. */
    private const int ELEMENTS = 10000;

    /** @var int Distinct keys at the ceiling a map repeated through a long list holds. */
    private const int REPEATED_KEYS = 10;

    /** @var int Rounds of the repeated keys split to measure this machine: a tenth of the long list. */
    private const int SAMPLED_ROUNDS = 1000;

    /** @var int The ceiling of either budget, so nothing is omitted. */
    private const int BUDGET_CEILING = 16777216;

    /** @var int How much a capture may grow to under a small process's limit, in bytes: 128 MiB. */
    private const int SMALL_PROCESS_BYTES = 134217728;

    /** @var string The memory limit before the test. */
    private string $memoryLimit = '';

    /**
     * Raise the memory limit, so a payload fails the growth assertion rather
     * than the engine's limit.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->memoryLimit = ini_get('memory_limit');

        ini_set('memory_limit', self::MEMORY_LIMIT);
    }

    /**
     * Restore the memory limit as far as the process allows: a limit below what
     * it still holds is refused.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        gc_mem_caches();

        $limit = ini_parse_quantity($this->memoryLimit);

        ini_set('memory_limit', $limit < 0 ? $this->memoryLimit : (string) max($limit, memory_get_usage(true)));

        parent::tearDown();
    }

    /**
     * A ten-megabyte string is cut to the retained cap, and nothing is omitted.
     *
     * @return void
     */
    public function testATenMegabyteString(): void
    {
        $pending = self::pending()->withProperties(['blob' => str_repeat('x', self::TEN_MEGABYTES)]);

        $minimised = $this->assertBounded($pending, self::permissive());

        self::assertSame(['blob' => str_repeat('x', FieldPolicy::STRING_MAX_BYTES)], $minimised->properties);
    }

    /**
     * A ten-megabyte string in the context is cut the same way.
     *
     * @return void
     */
    public function testATenMegabyteContextString(): void
    {
        $pending = self::pending();

        $pending->fillContext(['blob' => str_repeat('x', self::TEN_MEGABYTES)]);

        $minimised = $this->assertBounded($pending, self::permissive());

        self::assertSame(['blob' => str_repeat('x', FieldPolicy::STRING_MAX_BYTES)], $minimised->context);
        self::assertNull($minimised->properties);
    }

    /**
     * A ten-megabyte identifier is hashed whole and stored nowhere.
     *
     * @return void
     */
    public function testATenMegabyteIdentifier(): void
    {
        $pending = self::pending()->withIdentifier(str_repeat('A', self::TEN_MEGABYTES) . '@example.com');

        $minimised = $this->assertBounded($pending, self::permissive());

        self::assertMatchesRegularExpression('/\A\{"_audit":\{"identifier_hash":"[0-9a-f]{16}:[0-9a-f]{64}"\}\}\z/', self::encoded($minimised->properties));
    }

    /**
     * A list too long for the budget goes whole, by its masked path, since
     * omission stays at the top level.
     *
     * @return void
     */
    public function testATenThousandElementList(): void
    {
        $pending = self::pending()->withProperties(['items' => array_fill(0, self::ELEMENTS, 'an element long enough to exceed the budget'), 'kept' => 'kept']);

        $minimised = $this->assertBounded($pending, self::permissive());

        self::assertSame(['kept' => 'kept', '_audit' => ['omitted' => ['count' => 1, 'paths' => ['*']]]], $minimised->properties);
    }

    /**
     * A thousand levels stop at the deepest kept, on the builder, so nothing
     * walks them after.
     *
     * @return void
     */
    public function testAThousandLevelsOfNesting(): void
    {
        $nested = ['next' => 'leaf'];

        for ($level = 1; $level < 1000; $level++) {
            $nested = ['next' => $nested];
        }

        $minimised = $this->assertBounded(self::pending()->withProperties($nested), self::permissive());

        self::assertSame('{"next":{"next":{"next":{"next":{"next":{"next":{"next":{"next":"[TRUNCATED]"}}}}}}}}', self::encoded($minimised->properties));
    }

    /**
     * A hundred thousand equal-cost keys are costed and sorted once, keeping
     * the 512 bytewise lowest that fit beside the reserve.
     *
     * @return void
     */
    public function testAHundredThousandKeyWideMap(): void
    {
        $minimised = $this->assertBounded(self::pending()->withProperties(self::wideMap()), self::permissive());

        $properties = $minimised->properties ?? [];

        self::assertCount(513, $properties);
        self::assertSame('field_099488', array_key_first($properties));
        self::assertSame('_audit', array_key_last($properties));
        self::assertSame(['count' => 99488, 'paths' => ['*']], $properties['_audit']['omitted']);
    }

    /**
     * What is left of a wide map does not depend on the order of its keys.
     *
     * @return void
     */
    public function testTheOrderOfAWideMapChangesNothingKept(): void
    {
        $forward = $this->assertBounded(self::pending()->withProperties(self::wideMap()), self::permissive())->properties                      ?? [];
        $reverse = $this->assertBounded(self::pending()->withProperties(array_reverse(self::wideMap(), true)), self::permissive())->properties ?? [];

        ksort($forward);
        ksort($reverse);

        self::assertSame($forward, $reverse);
    }

    /**
     * A hundred thousand context keys stay within the context budget, and the
     * package's fixed names go last.
     *
     * @return void
     */
    public function testAHundredThousandKeyContext(): void
    {
        $pending = self::pending();

        $pending->fillContext(['route' => 'invoices.approve', ...self::wideMap()]);

        $minimised = $this->assertBounded($pending, self::permissive());

        $context = $minimised->context ?? [];

        self::assertArrayHasKey('route', $context);
        self::assertSame(['count' => 100001 - count($context), 'paths' => ['context.*']], $minimised->properties['_audit']['omitted'] ?? null);
    }

    /**
     * A megabyte key past the ceiling is never split and goes with its value,
     * leaving `*` to say so.
     *
     * @return void
     */
    public function testAMegabyteLongKey(): void
    {
        self::raiseThePropertyBudget();

        $pending = self::pending()->withProperties([str_repeat('aB', 524288) . '_password' => 'hunter2']);

        $minimised = $this->assertBounded($pending, self::permissive());

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['*']]]], $minimised->properties);
    }

    /**
     * Rows of `[bytes in the key]`: keys large enough to exhaust a 128 MiB
     * process if split a token at a time.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideHugeKeys(): iterable
    {
        yield from [
            '2 MiB' => [2097152],
            '8 MiB' => [8388608],
        ];
    }

    /**
     * A client's camel-cased map key of many megabytes costs no more than a
     * small process has, anywhere in the record. Only the key's own bytes are
     * allowed on top, since the request holds those anyway.
     *
     * @param  int  $bytes
     * @return void
     */
    #[DataProvider('provideHugeKeys')]
    public function testAClientsHugeKeyCannotExhaustASmallProcess(int $bytes): void
    {
        $key = str_repeat('aB', (int) ($bytes / 2));

        ini_set('memory_limit', (string) (memory_get_usage(true) + self::SMALL_PROCESS_BYTES));

        $pending = self::pending()->withProperties([$key => 'top', 'outer' => [$key => 'nested'], 'kept' => 'kept']);

        $pending->fillContext(['outer' => [$key => 'nested'], 'kept' => 'kept']);

        $minimised = $this->assertBounded($pending, self::permissive());

        self::assertSame(['outer' => [], 'kept' => 'kept', '_audit' => ['omitted' => ['count' => 3, 'paths' => ['*', 'context.*']]]], $minimised->properties);
        self::assertSame(['outer' => [], 'kept' => 'kept'], $minimised->context);
    }

    /**
     * A key at the ceiling is kept and judged, so its value is still redacted.
     *
     * @return void
     */
    public function testAKeyAtTheCeilingIsJudged(): void
    {
        self::raiseThePropertyBudget();

        $key = str_repeat('aB', (int) ((KeyCeiling::MAX_BYTES - 9) / 2)) . 'x_password';

        $minimised = $this->assertBounded(self::pending()->withProperties([$key => 'hunter2']), self::permissive());

        self::assertLessThanOrEqual(KeyCeiling::MAX_BYTES, strlen($key));
        self::assertSame([$key => Redactor::MARKER], $minimised->properties);
    }

    /**
     * With room in the budget every map of a long list is kept and walked for
     * secret keys.
     *
     * @return void
     */
    public function testATenThousandElementListOfMaps(): void
    {
        self::raiseThePropertyBudget();

        $minimised = $this->assertBounded(self::pending()->withProperties(['items' => self::listOfMaps()]), self::permissive());

        $kept = ['sku' => 'A-1', 'qty' => 2, 'password' => Redactor::MARKER, 'description' => 'a description long enough'];

        self::assertSame(['items' => array_fill(0, self::ELEMENTS, $kept)], $minimised->properties);
    }

    /**
     * With no room in the budget the list goes whole, once it has been walked.
     *
     * @return void
     */
    public function testATenThousandElementListOfMapsOverItsBudget(): void
    {
        $minimised = $this->assertBounded(self::pending()->withProperties(['items' => self::listOfMaps()]), self::permissive());

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['*']]]], $minimised->properties);
    }

    /**
     * Ten thousand maps sharing a few ceiling-length keys are judged faster
     * than splitting every occurrence, since each distinct key is split once
     * per capture.
     *
     * @return void
     */
    public function testKeysRepeatedThroughALongListAreSplitOnce(): void
    {
        self::raiseThePropertyBudget();

        $map = [];

        foreach (range(1, self::REPEATED_KEYS) as $index) {
            $map[str_pad((string) $index, KeyCeiling::MAX_BYTES, 'aB')] = 1;
        }

        $pending = self::pending()->withProperties(['items' => array_fill(0, self::ELEMENTS, $map)]);

        $minimised = $this->assertBounded($pending, self::permissive(), self::nanosecondsToSplitEveryOccurrence(array_keys($map)));

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['*']]]], $minimised->properties);
    }

    /**
     * A rule beneath a wildcard applies to every map of a long list, unnamed
     * fields counted under a path masked whole, and the list goes under the
     * rule's name once it cannot fit.
     *
     * @return void
     */
    public function testANestedWildcardRuleOverTenThousandMaps(): void
    {
        $maps = array_fill(0, self::ELEMENTS, ['sku' => 'A-1', 'customer' => 'Alice Example']);

        $minimised = $this->assertBounded(self::pending()->withProperties(['items' => $maps]), EventDefinition::for(self::CODE)->retain('items.*.sku'));

        self::assertSame(['_audit' => ['omitted' => ['count' => self::ELEMENTS + 1, 'paths' => ['*.*.*', 'items']]]], $minimised->properties);
    }

    /**
     * A wildcard hashes each of ten thousand values under its one rule, and the
     * list goes whole under the rule's name once it cannot fit.
     *
     * @return void
     */
    public function testAWildcardPseudonymiseOverTenThousandElements(): void
    {
        $emails = array_map(static fn (int $index): string => "person{$index}@example.com", range(1, self::ELEMENTS));

        $minimised = $this->assertBounded(self::pending()->withProperties(['items' => $emails]), EventDefinition::for(self::CODE)->pseudonymise('items.*'));

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['items']]]], $minimised->properties);
    }

    /**
     * An encrypter that throws is called and reported once per capture, every
     * value is dropped under the rule's one path, and the plaintext is nowhere.
     *
     * @return void
     */
    public function testAWildcardEncryptWithAThrowingEncrypterReportsOnce(): void
    {
        $encrypter = new ThrowingFieldEncrypter;
        $handler   = new RecordingExceptionHandler;

        app()->instance(FieldEncrypter::class, $encrypter);
        app()->instance(ExceptionHandler::class, $handler);

        $pending = self::pending()->by(Reference::of('user', '7'))->withProperties(['items' => array_fill(0, self::ELEMENTS, 'plaintext')]);

        $minimised = $this->assertBounded($pending, EventDefinition::for(self::CODE)->encrypt('items.*', KeyOwner::ACTOR));

        self::assertSame(['_audit' => ['omitted' => ['count' => self::ELEMENTS, 'paths' => ['items.*']]]], $minimised->properties);
        self::assertSame(2, $encrypter->calls());
        self::assertCount(2, $handler->reports());
    }

    /**
     * Ten thousand keys that collide once cleaned keep the path list to its
     * bound, count every one, and write none in the diagnostics.
     *
     * @return void
     */
    public function testTenThousandCollidingKeys(): void
    {
        $colliding = [];

        for ($index = 0; $index < self::ELEMENTS; $index++) {
            $colliding['bob@example.com' . strtr(decbin($index), '01', "\1\2")] = $index;
        }

        $minimised = $this->assertBounded(self::pending()->withProperties($colliding), self::permissive());

        self::assertSame(['bob@example.com' => 0, '_audit' => ['omitted' => ['count' => self::ELEMENTS - 1, 'paths' => ['*']]]], $minimised->properties);
    }

    /**
     * Both captures of the payload stay within their bounds and give the same
     * result. Callers compare diagnostics whole, which is what shows no value
     * reached them.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  int  $maxNanoseconds
     * @return \SineMacula\Laravel\AuditLog\Privacy\Minimised
     */
    private function assertBounded(PendingRecord $pending, EventDefinition $definition, int $maxNanoseconds = self::MAX_NANOSECONDS): Minimised
    {
        $snapshot = $pending->snapshot();
        $settings = app(RedactionSettings::class);

        $first  = self::measured($snapshot, $definition, $maxNanoseconds);
        $second = self::measured($snapshot, $definition, $maxNanoseconds);

        self::assertLessThanOrEqual($settings->maxBytes(), strlen(self::encoded($first->properties)));
        self::assertLessThanOrEqual($settings->maxContextBytes(), strlen(self::encoded($first->context)));
        self::assertSame($first->properties, $second->properties);
        self::assertSame($first->context, $second->context);
        self::assertSame($first->ip, $second->ip);

        return $first;
    }

    /**
     * One capture of the snapshot by its own minimiser, within the memory and
     * time bounds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  int  $maxNanoseconds
     * @return \SineMacula\Laravel\AuditLog\Privacy\Minimised
     */
    private static function measured(PendingSnapshot $snapshot, EventDefinition $definition, int $maxNanoseconds): Minimised
    {
        $minimiser = app(RecordMinimiser::class);

        memory_reset_peak_usage();

        $before  = memory_get_usage();
        $started = self::cpuNanoseconds();

        $minimised = $minimiser->minimise($snapshot, $definition, self::ENTRY_ID);

        $elapsed = self::cpuNanoseconds()  - $started;
        $growth  = memory_get_peak_usage() - $before;

        self::assertLessThan(self::MAX_MEMORY_GROWTH, $growth, sprintf('The capture grew the peak by %d bytes.', $growth));

        if (!self::isCollectingCoverage()) {
            self::assertLessThan($maxNanoseconds, $elapsed, sprintf('The capture used %.3f seconds of CPU.', $elapsed / 1000000000));
        }

        return $minimised;
    }

    /**
     * The CPU time splitting the keys in every map of the long list takes on
     * this machine, measured on a tenth of the list.
     *
     * @param  list<int|string>  $keys
     * @return int
     */
    private static function nanosecondsToSplitEveryOccurrence(array $keys): int
    {
        $started = self::cpuNanoseconds();

        for ($round = 0; $round < self::SAMPLED_ROUNDS; $round++) {
            foreach ($keys as $key) {
                KeyTokenizer::tokens((string) $key);
            }
        }

        return (self::cpuNanoseconds() - $started) * intdiv(self::ELEMENTS, self::SAMPLED_ROUNDS);
    }

    /**
     * The CPU time this process has used, user and system: waiting for a core
     * uses none of it.
     *
     * @return int
     */
    private static function cpuNanoseconds(): int
    {
        $usage = getrusage();

        assert(is_array($usage));

        return ($usage['ru_utime.tv_sec'] + $usage['ru_stime.tv_sec'])  * 1000000000
            + ($usage['ru_utime.tv_usec'] + $usage['ru_stime.tv_usec']) * 1000;
    }

    /**
     * Whether Xdebug is collecting coverage in this process.
     *
     * @return bool
     */
    private static function isCollectingCoverage(): bool
    {
        return function_exists('xdebug_info') && in_array('coverage', xdebug_info('mode'), true);
    }

    /**
     * Raise the property budget to its ceiling, so nothing is omitted and what
     * was done to a value shows.
     *
     * @return void
     */
    private static function raiseThePropertyBudget(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.max_bytes', self::BUDGET_CEILING);
    }

    /**
     * Ten thousand maps, each with a secret-shaped key among others.
     *
     * @return list<array<string, int|string>>
     */
    private static function listOfMaps(): array
    {
        return array_fill(0, self::ELEMENTS, ['sku' => 'A-1', 'qty' => 2, 'password' => 'hunter2', 'description' => 'a description long enough']);
    }

    /**
     * A hundred thousand keys, each costing the same.
     *
     * @return array<string, string>
     */
    private static function wideMap(): array
    {
        $map = [];

        for ($index = 0; $index < 100000; $index++) {
            $map[sprintf('field_%06d', $index)] = 'value';
        }

        return $map;
    }

    /**
     * A value as it is stored and measured.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?array<array-key, mixed>  $value
     * @return string
     */
    private static function encoded(?array $value): string
    {
        return json_encode($value ?? [], CanonicalEncoder::JSON_FLAGS);
    }

    /**
     * A builder of the code, holding nothing else.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function pending(): PendingRecord
    {
        return (new PendingRecord)->event(self::CODE);
    }

    /**
     * The definition of an unregistered code.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    private static function permissive(): EventDefinition
    {
        return EventDefinition::permissive(EventCode::of(self::CODE));
    }
}
