<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Keys\KeySettings;

/**
 * Unit tests for the owners' key settings: the explicit wrapping ring decoded
 * as the integrity ring is, the current key set with it or not at all, the
 * application keys read through the integrity settings, the rewrap batch and
 * its range, validation that never reads the application keys beside an
 * explicit ring, and refusals that name the setting and never a secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeySettings::class)]
final class KeySettingsTest extends TestCase
{
    /** @var string `app.key` as Laravel stores it. */
    private const string APP_KEY = 'base64:bGFyYXZlbC1hdWRpdC1sb2cgdGVzdCBrZXkhISEhISE=';

    /** @var string The bytes `APP_KEY` decodes to. */
    private const string APP_KEY_BYTES = 'laravel-audit-log test key!!!!!!';

    /** @var string A raw secret of exactly 32 bytes. */
    private const string RAW_SECRET = 'explicit-wrap-secret-of-32-bytes';

    /** @var string Why a ring that is not a map is refused. */
    private const string KEYS_NOT_A_MAP = '`audit-log.privacy.keys` must be a map of key ids to secrets, or empty to derive the wrapping key from `app.key`.';

    /** @var string Why a key id outside the grammar is refused. */
    private const string BAD_ID = '`audit-log.privacy.keys` has a key id that is not 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';

    /** @var string Why a secret is refused, by its key id. */
    private const string BAD_SECRET = '`audit-log.privacy.keys.%s` must be a secret of at least 32 bytes, or `base64:` followed by the encoding of one.';

    /** @var string Why a current key id outside the ring is refused. */
    private const string CURRENT_NOT_IN_RING = '`audit-log.privacy.current` must name a key in `audit-log.privacy.keys`.';

    /** @var string Why a current key id beside an empty ring is refused. */
    private const string CURRENT_WITHOUT_KEYS = '`audit-log.privacy.current` names a key, but `audit-log.privacy.keys` is empty;'
        . ' set both, or neither to derive the wrapping key from `app.key`.';

    /** @var string Why a rewrap batch out of range is refused. */
    private const string BAD_BATCH = '`audit-log.privacy.rewrap_batch` must be an integer from 100 to 10000.';

    /**
     * With no ring, there are no explicit keys and no current key id, and the
     * key is derived from the application keys.
     *
     * @return void
     */
    public function testWithoutKeysNoExplicitRingIsConfigured(): void
    {
        foreach ([[], ['keys' => null, 'current' => null], ['keys' => [], 'current' => ''], ['keys' => [], 'current' => null]] as $privacy) {
            $settings = self::settings($privacy);

            self::assertSame([], $settings->explicitKeys());
            self::assertNull($settings->currentKeyId());
            self::assertSame([self::APP_KEY_BYTES], $settings->applicationKeys());
        }
    }

    /**
     * An explicit ring's secrets are decoded, raw and `base64:` alike, a
     * numeric id is read as the integer key PHP makes of it, and the current
     * key id is read.
     *
     * @return void
     */
    public function testAnExplicitRingIsDecodedAndItsCurrentKeyRead(): void
    {
        $settings = self::settings(['keys' => ['w1' => self::RAW_SECRET, 2026 => 'base64:' . base64_encode(str_repeat("\1", 32))], 'current' => '2026']);

        self::assertSame(['w1' => self::RAW_SECRET, 2026 => str_repeat("\1", 32)], $settings->explicitKeys());
        self::assertSame('2026', $settings->currentKeyId());
        self::assertSame('w1', self::settings(['keys' => ['w1' => self::RAW_SECRET], 'current' => 'w1'])->currentKeyId());
    }

    /**
     * Rows of `[privacy settings, message]`: every malformed ring or current
     * key id, and the message it fails with.
     *
     * @return iterable<string, array{0: array<string, array<int|string, array<int, string>|int|string|null>|bool|int|string|null>, 1: string}>
     */
    public static function provideMalformedRings(): iterable
    {
        yield from [
            'keys a string'                 => [['keys' => 'w1'], self::KEYS_NOT_A_MAP],
            'keys true'                     => [['keys' => true], self::KEYS_NOT_A_MAP],
            'an id with a leading dot'      => [['keys' => ['.w1' => self::RAW_SECRET], 'current' => '.w1'], self::BAD_ID],
            'an id of 33 characters'        => [['keys' => [str_repeat('w', 33) => self::RAW_SECRET]], self::BAD_ID],
            'an id with a colon'            => [['keys' => ['kms:w1' => self::RAW_SECRET]], self::BAD_ID],
            'a negative integer id'         => [['keys' => [-1 => self::RAW_SECRET]], self::BAD_ID],
            'a null secret'                 => [['keys' => ['w1' => null], 'current' => 'w1'], sprintf(self::BAD_SECRET, 'w1')],
            'a list secret'                 => [['keys' => ['w1' => [self::RAW_SECRET]], 'current' => 'w1'], sprintf(self::BAD_SECRET, 'w1')],
            'a 31-byte secret'              => [['keys' => ['w1' => str_repeat('s', 31)], 'current' => 'w1'], sprintf(self::BAD_SECRET, 'w1')],
            'a secret that does not decode' => [['keys' => ['w1' => 'base64:' . str_repeat('!', 44)], 'current' => 'w1'], sprintf(self::BAD_SECRET, 'w1')],
            'a bad entry beside a good one' => [['keys' => ['good' => self::RAW_SECRET, 'bad' => 'short'], 'current' => 'good'], sprintf(self::BAD_SECRET, 'bad')],
            'current not a string'          => [['keys' => ['1' => self::RAW_SECRET], 'current' => 1], self::CURRENT_NOT_IN_RING],
            'current unset with keys'       => [['keys' => ['w1' => self::RAW_SECRET]], self::CURRENT_NOT_IN_RING],
            'current empty with keys'       => [['keys' => ['w1' => self::RAW_SECRET], 'current' => ''], self::CURRENT_NOT_IN_RING],
            'current naming no key'         => [['keys' => ['w1' => self::RAW_SECRET], 'current' => 'w2'], self::CURRENT_NOT_IN_RING],
            'current differing in case'     => [['keys' => ['w1' => self::RAW_SECRET], 'current' => 'W1'], self::CURRENT_NOT_IN_RING],
            'current not a string, no keys' => [['current' => 1], self::CURRENT_NOT_IN_RING],
            'current with empty keys'       => [['keys' => [], 'current' => 'w1'], self::CURRENT_WITHOUT_KEYS],
            'current with keys unset'       => [['current' => 'w1'], self::CURRENT_WITHOUT_KEYS],
        ];
    }

    /**
     * Each malformed ring or current key id fails closed with its message from
     * `currentKeyId()` and `validate()`, even beside a valid `app.key`, so no
     * reader ever falls back to the derived ring.
     *
     * @param  array<string, array<int|string, array<int, string>|int|string|null>|bool|int|string|null>  $privacy
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedRings')]
    public function testAMalformedRingFailsClosedNamingTheSetting(array $privacy, string $message): void
    {
        $settings = self::settings($privacy);

        self::assertRefused($message, $settings->currentKeyId(...));
        self::assertRefused($message, $settings->validate(...));
    }

    /**
     * The application keys are `app.key`, then each previous key, decoded, as
     * the integrity settings read them, and fail closed as they do.
     *
     * @return void
     */
    public function testTheApplicationKeysAreReadThroughTheIntegritySettings(): void
    {
        $settings = self::settings([], ['key' => self::APP_KEY, 'previous_keys' => [self::RAW_SECRET]]);

        self::assertSame([self::APP_KEY_BYTES, self::RAW_SECRET], $settings->applicationKeys());
        self::assertRefused('`app.key` must be set to derive the integrity key when `audit-log.integrity.keys` is empty.', self::settings([], [])->applicationKeys(...));
    }

    /**
     * Rows of `[setting, the batch read]`: the default, the range's ends, and
     * the digit string an environment variable gives.
     *
     * @return iterable<string, array{0: int|string|null, 1: int}>
     */
    public static function provideBatches(): iterable
    {
        yield from [
            'unset'          => [null, 500],
            'the least'      => [100, 100],
            'the greatest'   => [10000, 10000],
            'a digit string' => ['250', 250],
        ];
    }

    /**
     * The rewrap batch is the setting, from 100 to 10000, or 500 when unset.
     *
     * @param  int|string|null  $batch
     * @param  int  $expected
     * @return void
     */
    #[DataProvider('provideBatches')]
    public function testTheRewrapBatchIsReadInItsRange(int|string|null $batch, int $expected): void
    {
        self::assertSame($expected, self::settings($batch === null ? [] : ['rewrap_batch' => $batch])->rewrapBatch());
    }

    /**
     * Rows of `[setting]`: batches below and above the range, and values that
     * are not integers.
     *
     * @return iterable<string, array{0: bool|float|int|string}>
     */
    public static function provideRefusedBatches(): iterable
    {
        yield from [
            'one too few'   => [99],
            'one too many'  => [10001],
            'zero'          => [0],
            'a float'       => [500.0],
            'padded digits' => ['0500'],
            'a word'        => ['many'],
            'true'          => [true],
        ];
    }

    /**
     * A batch out of range, or not an integer, fails closed naming the setting,
     * from `rewrapBatch()` and `validate()`.
     *
     * @param  bool|float|int|string  $batch
     * @return void
     */
    #[DataProvider('provideRefusedBatches')]
    public function testARewrapBatchOutOfRangeIsRefused(bool|float|int|string $batch): void
    {
        $settings = self::settings(['rewrap_batch' => $batch]);

        self::assertRefused(self::BAD_BATCH, $settings->rewrapBatch(...));
        self::assertRefused(self::BAD_BATCH, $settings->validate(...));
    }

    /**
     * Validation reads the application keys only when no ring is set: an
     * explicit ring validates with no `app.key`, and without one a missing
     * `app.key` fails it.
     *
     * @return void
     */
    public function testValidateReadsTheApplicationKeysOnlyWithoutARing(): void
    {
        self::settings(['keys' => ['w1' => self::RAW_SECRET], 'current' => 'w1'], [])->validate();
        self::settings([], ['key' => self::APP_KEY])->validate();

        self::assertRefused('`app.key` must be set to derive the integrity key when `audit-log.integrity.keys` is empty.', self::settings([], [])->validate(...));
    }

    /**
     * Settings are read on every call, so a change to the configuration is seen
     * by the next call without a new instance.
     *
     * @return void
     */
    public function testSettingsAreReadOnEveryCall(): void
    {
        $config   = new Repository(['audit-log' => ['privacy' => []], 'app' => ['key' => self::APP_KEY]]);
        $settings = new KeySettings($config, new IntegritySettings($config));

        self::assertNull($settings->currentKeyId());
        self::assertSame(500, $settings->rewrapBatch());

        $config->set('audit-log.privacy.keys', ['w1' => self::RAW_SECRET]);
        $config->set('audit-log.privacy.current', 'w1');
        $config->set('audit-log.privacy.rewrap_batch', 1000);
        $config->set('app.key', self::RAW_SECRET);

        self::assertSame('w1', $settings->currentKeyId());
        self::assertSame(1000, $settings->rewrapBatch());
        self::assertSame([self::RAW_SECRET], $settings->applicationKeys());
    }

    /**
     * No refusal of a secret shows the secret, in its message or in the
     * arguments of the settings' own frames of its stack trace.
     *
     * @return void
     */
    public function testNoMessageContainsASecret(): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            self::settings(['keys' => ['w1' => 'leaked-short-secret'], 'current' => 'w1'])->validate();
            self::fail('Expected the secret to be refused.');
        } catch (\InvalidArgumentException $exception) {
            $frames = array_filter($exception->getTrace(), static fn (array $frame): bool => ($frame['class'] ?? null) === KeySettings::class);
            $shown  = $exception->getMessage() . print_r($frames, true);

            self::assertNotSame([], $frames);
            self::assertStringNotContainsString('leaked', $shown);
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '0' : $previous);
        }
    }

    /**
     * Assert the call fails closed with exactly the message.
     *
     * @param  string  $message
     * @param  \Closure(): (array<int|string, string>|int|string|null)  $call
     * @return void
     */
    private static function assertRefused(string $message, \Closure $call): void
    {
        try {
            $call();
            self::fail(sprintf('Expected the call to be refused with: %s', $message));
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }
    }

    /**
     * Settings over a plain repository holding the privacy settings and the
     * application settings given.
     *
     * @param  array<string, array<int|string, array<int, string>|int|string|null>|bool|float|int|string|null>  $privacy
     * @param  array<string, list<string>|string>  $app
     * @return \SineMacula\Laravel\AuditLog\Keys\KeySettings
     */
    private static function settings(array $privacy, array $app = ['key' => self::APP_KEY]): KeySettings
    {
        $config = new Repository(['audit-log' => ['privacy' => $privacy], 'app' => $app]);

        return new KeySettings($config, new IntegritySettings($config));
    }
}
