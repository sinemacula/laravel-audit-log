<?php

declare(strict_types = 1);

namespace Tests\Feature\Stores;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Monolog\Formatter\LineFormatter;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Delivery\SpillReader;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\DocumentedSpillChannel;
use Tests\Fixtures\Stores\ThrowingLogHandler;
use Tests\TestCase;

/**
 * Feature tests for the spill: the one line a failed write leaves, at
 * `critical`, on the configured channel; the marker and the canonical envelope
 * it holds, signed or marked `unsigned`, a record with an attachment as its
 * whole bundle, which the codec reads back; that it stays one physical line and
 * holds no `%`, so the documented channel writes it back byte for byte; and
 * that a failed channel propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureSpill::class)]
final class FailureSpillTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore;

    /** @var string The documented spill channel's name. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var string The application's own default channel, writing to a file of its own. */
    private const string DEFAULT_CHANNEL = 'application';

    /** @var string A value holding every kind of line break a log could split on. */
    private const string LINE_BREAKS = "one\rtwo\nthree\r\nfour\u{2028}five\u{2029}six";

    /** @var array<string, string> The log files this test created, by channel. */
    private array $files = [];

    /**
     * Give the documented channel and the application's default channel a file
     * each, so nothing a test spills reaches another log.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $config = app(ConfigRepository::class);

        foreach ([self::SPILL_CHANNEL, self::DEFAULT_CHANNEL] as $channel) {
            $this->files[$channel] = sys_get_temp_dir() . '/audit-log-' . $channel . '-' . bin2hex(random_bytes(8)) . '.log';
        }

        $config->set('logging.channels.' . self::SPILL_CHANNEL, DocumentedSpillChannel::config($this->files[self::SPILL_CHANNEL]));
        $config->set('logging.channels.' . self::DEFAULT_CHANNEL, ['driver' => 'single', 'path' => $this->files[self::DEFAULT_CHANNEL], 'level' => 'debug']);
        $config->set('logging.default', self::DEFAULT_CHANNEL);
    }

    /**
     * Delete the log files this test created.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        $this->files = [];

        parent::tearDown();
    }

    /**
     * A spill is one message, at `critical`.
     *
     * @return void
     */
    public function testWritesOneLineAtCritical(): void
    {
        $this->captureLogLines();

        $this->spill()->spillFinalised($this->finalisedWith());

        self::assertCount(1, $this->loggedMessages());
        self::assertSame('critical', $this->loggedMessages()[0]->level);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * The line is the marker, then the finalised record's envelope in the
     * canonical encoding, integrity fields included.
     *
     * @return void
     */
    public function testTheLineIsTheMarkerAndTheCanonicalEnvelope(): void
    {
        $record = $this->finalisedWith();

        $this->captureLogLines();

        $this->spill()->spillFinalised($record);

        $line = FailureSpill::MARKER . CanonicalEncoder::encode($record->toArray());

        self::assertSame([$line], $this->spillLines());
        self::assertSame($line, FailureSpill::line($record->toArray()));
        self::assertSame('audit-log-spill:v1 ', FailureSpill::MARKER);
        self::assertSame($record->hmac, $this->decoded($line)['hmac']);
    }

    /**
     * A carriage return and a line feed in a value are written as their JSON
     * escapes, never as the characters.
     *
     * @return void
     */
    public function testEscapesCrAndLf(): void
    {
        $record = $this->finalisedWith(['reason' => "denied\r\nby policy", 'properties' => ['note' => "a\rb\nc"]]);

        $this->captureLogLines();

        $this->spill()->spillFinalised($record);

        $line = $this->spillLines()[0];

        self::assertStringNotContainsString("\r", $line);
        self::assertStringNotContainsString("\n", $line);
        self::assertStringContainsString('"reason":"denied\r\nby policy"', $line);
        self::assertStringContainsString('"note":"a\rb\nc"', $line);
    }

    /**
     * A value built to forge a second spill line, with every line break and a
     * marker of its own, stays inside its string on the one line, and decodes
     * back to itself.
     *
     * @return void
     */
    public function testAHostileValueStaysOnOneLine(): void
    {
        $hostile = self::LINE_BREAKS . "\n" . FailureSpill::MARKER . '{"id":"forged"}' . "\n";
        $record  = $this->finalisedWith(['properties' => ['note' => $hostile]]);

        $this->captureLogLines();

        $this->spill()->spillFinalised($record);

        $line = $this->spillLines()[0];

        self::assertStringStartsWith(FailureSpill::MARKER, $line);
        self::assertSame(0, preg_match('/[\r\n\x{2028}\x{2029}]/u', $line));
        self::assertSame($hostile, $this->decoded($line)['properties']['note']);
    }

    /**
     * The line goes to the configured channel, and to no other.
     *
     * @return void
     */
    public function testUsesTheConfiguredChannel(): void
    {
        $this->spillTo(self::SPILL_CHANNEL);

        $record = $this->finalisedWith();

        $this->spill()->spillFinalised($record);

        self::assertSame(FailureSpill::line($record->toArray()) . "\n", $this->contentsOf(self::SPILL_CHANNEL));
        self::assertSame('', $this->contentsOf(self::DEFAULT_CHANNEL));
    }

    /**
     * Rows of `[setting]`: the values of `audit-log.failure.log_channel` that
     * mean the default channel.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideDefaultChannelSettings(): iterable
    {
        yield from [
            'null'  => [null],
            'empty' => [''],
        ];
    }

    /**
     * With no channel configured, the line goes to the application's default
     * channel.
     *
     * @param  ?string  $setting
     * @return void
     */
    #[DataProvider('provideDefaultChannelSettings')]
    public function testUsesTheDefaultChannelWhenNoneIsConfigured(?string $setting): void
    {
        $this->spillTo($setting);

        $this->spill()->spillFinalised($this->finalisedWith());

        self::assertStringContainsString(FailureSpill::MARKER, $this->contentsOf(self::DEFAULT_CHANNEL));
        self::assertSame('', $this->contentsOf(self::SPILL_CHANNEL));
    }

    /**
     * A record that was never finalised is spilled marked `unsigned`, with its
     * captured fields and no integrity field.
     *
     * @return void
     */
    public function testAnUnsignedSpillIsMarkedAndHoldsNoSignature(): void
    {
        $record = RecordFactory::captured();

        $this->captureLogLines();

        $this->spill()->spillUnsigned($record);

        $line    = $this->spillLines()[0];
        $decoded = $this->decoded($line);
        $keys    = ['unsigned', ...array_keys($record->toArray())];

        sort($keys);

        self::assertSame(FailureSpill::MARKER . CanonicalEncoder::encode(['unsigned' => true, ...$record->toArray()]), $line);
        self::assertTrue($decoded['unsigned']);
        self::assertSame($keys, array_keys($decoded));

        foreach (['recorded_at', 'integrity_version', 'key_id', 'hmac'] as $column) {
            self::assertArrayNotHasKey($column, $decoded, "An unsigned spill holds `{$column}`.");
        }
    }

    /**
     * A finalised record with an attachment is spilled as its whole bundle: the
     * bundle version, the record's signed columns, and the attachment naming
     * the record as its entry, its sealed members as they were.
     *
     * @return void
     */
    public function testASpilledBundleHoldsItsAttachment(): void
    {
        $record     = $this->finaliser()->finalise(RecordFactory::bundled());
        $attachment = $record->record->attachment;

        self::assertNotNull($attachment);

        $this->captureLogLines();

        $this->spill()->spillFinalised($record);

        $line    = $this->spillLines()[0];
        $decoded = $this->decoded($line);

        self::assertSame(FailureSpill::MARKER . CanonicalEncoder::encode(EnvelopeCodec::envelopeOf($record)), $line);
        self::assertSame(['attachment', 'bundle_version', 'record'], array_keys($decoded));
        self::assertSame(EnvelopeCodec::BUNDLE_VERSION, $decoded['bundle_version']);
        self::assertSame(CanonicalEncoder::encode($attachment->envelopeFor($record->record->id)), CanonicalEncoder::encode($decoded['attachment']));
        self::assertSame(CanonicalEncoder::encode($record->toArray()), CanonicalEncoder::encode($decoded['record']));
        self::assertSame($record->record->id, $decoded['attachment']['entry_id']);
        self::assertSame($attachment->members, $decoded['attachment']['members']);
        self::assertSame($record->hmac, $decoded['record']['hmac']);
    }

    /**
     * A record with an attachment that was never finalised is spilled as its
     * bundle marked `unsigned`, the attachment beside its record, and no
     * integrity field in the record.
     *
     * @return void
     */
    public function testAnUnsignedBundleIsMarkedAndHoldsItsAttachment(): void
    {
        $record     = RecordFactory::bundled();
        $attachment = $record->attachment;

        self::assertNotNull($attachment);

        $this->captureLogLines();

        $this->spill()->spillUnsigned($record);

        $line    = $this->spillLines()[0];
        $decoded = $this->decoded($line);

        self::assertSame(FailureSpill::MARKER . CanonicalEncoder::encode(EnvelopeCodec::unsignedEnvelopeOf($record)), $line);
        self::assertSame(['attachment', 'bundle_version', 'record', 'unsigned'], array_keys($decoded));
        self::assertTrue($decoded['unsigned']);
        self::assertSame(CanonicalEncoder::encode($attachment->envelopeFor($record->id)), CanonicalEncoder::encode($decoded['attachment']));
        self::assertSame(CanonicalEncoder::encode($record->toArray()), CanonicalEncoder::encode($decoded['record']));

        foreach (['recorded_at', 'integrity_version', 'key_id', 'hmac'] as $column) {
            self::assertArrayNotHasKey($column, $decoded['record'], "An unsigned bundle's record holds `{$column}`.");
        }
    }

    /**
     * A bundle spilled through the documented channel reads back through the
     * codec as the same record with the same attachment, whose members open to
     * the manifest's canonical form; the unsigned bundle beside it is refused
     * as unsigned, naming its record.
     *
     * @return void
     */
    public function testASpilledBundleReadsBackThroughTheCodec(): void
    {
        $this->spillTo(self::SPILL_CHANNEL);

        $record   = $this->finaliser()->finalise(RecordFactory::bundled());
        $unsigned = RecordFactory::bundled();

        $this->spill()->spillFinalised($record);
        $this->spill()->spillUnsigned($unsigned);

        $lines = explode("\n", $this->contentsOf(self::SPILL_CHANNEL));
        $codec = app(EnvelopeCodec::class);

        self::assertCount(3, $lines);

        $json = SpillReader::extract($lines[0]);

        self::assertIsString($json);

        $decoded = $codec->decode($json, $record->record->id);

        self::assertSame($codec->encode($record), $codec->encode($decoded));
        self::assertEquals($record->record->attachment, $decoded->record->attachment);
        self::assertNotNull($decoded->record->attachment);

        self::assertNotNull($decoded->record->attachment->members);

        $members = app(StringEncrypter::class)->decryptString($decoded->record->attachment->members);

        self::assertSame(['count' => 3, 'digest' => $decoded->record->attachment->digest], Manifest::readCanonical($members));

        try {
            $codec->decode((string) SpillReader::extract($lines[1]));

            self::fail('Expected the unsigned bundle to be refused.');
        } catch (EnvelopeRejectedException $exception) {
            self::assertSame(EnvelopeFailure::UNSIGNED, $exception->failure);
            self::assertSame($unsigned->id, $exception->id);
        }
    }

    /**
     * A `%` anywhere in a bundle's record is written as its JSON escape, as in
     * any other line, so the bundle's line holds none, and its record still
     * verifies once it is read back.
     *
     * @return void
     */
    public function testABundlesLineHoldsNoPercentSign(): void
    {
        $bundled    = RecordFactory::bundled();
        $properties = [...(array) $bundled->properties, 'share' => '100%', '%key%' => '%%s'];
        $record     = $this->finaliser()->finalise(RecordFactory::withFields(['properties' => $properties, 'attachment' => $bundled->attachment], $bundled));

        $this->captureLogLines();

        $this->spill()->spillFinalised($record);

        $line = $this->spillLines()[0];

        self::assertStringNotContainsString('%', $line);
        self::assertSame(FailureSpill::line(EnvelopeCodec::envelopeOf($record)), $line);
        self::assertSame($record->hmac, app(EnvelopeCodec::class)->decode(substr($line, strlen(FailureSpill::MARKER)))->hmac);
    }

    /**
     * A channel that fails propagates its own exception to the caller, which is
     * the one to isolate it, and nothing is logged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedChannelPropagatesToItsCaller(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('logging.channels.broken', ThrowingLogHandler::channel());
        $config->set('audit-log.failure.log_channel', 'broken');

        $this->captureLogLines();

        try {
            $this->spill()->spillFinalised($this->finalisedWith());

            self::fail('Expected the channel\'s failure to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The log is unreachable: ' . ThrowingLogHandler::SECRET, $exception->getMessage());
        }

        self::assertSame([], $this->loggedMessages());
    }

    /**
     * A failure raised beneath the spill shows no value of the record in any
     * frame of the spill, so the caller can report its class safely.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedChannelShowsNoRecordInTheSpillsFrames(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('logging.channels.broken', ThrowingLogHandler::channel());
        $config->set('audit-log.failure.log_channel', 'broken');

        $failures = [];

        foreach ([fn () => $this->spill()->spillFinalised($this->finalisedWith()), fn () => $this->spill()->spillUnsigned(RecordFactory::captured())] as $spill) {
            try {
                $spill();
            } catch (\RuntimeException $exception) {
                $failures[] = $exception;
            }
        }

        self::assertCount(2, $failures);

        foreach ($failures as $failure) {
            $frames = array_filter($failure->getTrace(), static fn (array $frame): bool => ($frame['class'] ?? null) === FailureSpill::class);

            self::assertNotSame([], $frames);

            foreach ($frames as $frame) {
                foreach ($frame['args'] ?? [] as $argument) {
                    self::assertInstanceOf(\SensitiveParameterValue::class, $argument, "The spill's {$frame['function']}() shows an argument.");
                }
            }
        }
    }

    /**
     * A malformed channel setting fails closed rather than spilling anywhere.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMalformedChannelSettingIsRefused(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.log_channel', ['audit-spill']);

        $this->captureLogLines();

        try {
            $this->spill()->spillFinalised($this->finalisedWith());

            self::fail('Expected the setting to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('audit-log.failure.log_channel', $exception->getMessage());
        }

        self::assertSame([], $this->loggedMessages());
    }

    /**
     * The line carries no context, so a channel's format adds nothing of the
     * record after it.
     *
     * @return void
     */
    public function testHasNoContext(): void
    {
        $this->captureLogLines();

        $this->spill()->spillFinalised($this->finalisedWith());
        $this->spill()->spillUnsigned(RecordFactory::captured());

        self::assertCount(2, $this->loggedMessages());
        self::assertSame([], $this->loggedMessages()[0]->context);
        self::assertSame([], $this->loggedMessages()[1]->context);
    }

    /**
     * The whole record reaches no `MessageLogged` listener, so it cannot land
     * among an error tracker's breadcrumbs beside the report that follows it,
     * and no shared log context joins the line.
     *
     * @return void
     */
    public function testNoListenerAndNoSharedContextReachTheLine(): void
    {
        $heard = [];

        Event::listen(MessageLogged::class, static function (MessageLogged $logged) use (&$heard): void {
            $heard[] = $logged->message;
        });

        $this->captureLogLines();

        Log::shareContext(['forged' => 'value']);

        $this->spill()->spillFinalised($this->finalisedWith());

        self::assertSame([], $heard);
        self::assertCount(1, $this->spillLines());
        self::assertSame([], $this->loggedMessages()[0]->context);
    }

    /**
     * A value of 1 MiB is spilled whole: the line is never truncated.
     *
     * @return void
     */
    public function testNeverTruncates(): void
    {
        $large  = str_repeat('a', 1048575) . 'z';
        $record = $this->finalisedWith(['properties' => ['note' => $large]]);

        $this->captureLogLines();

        $this->spill()->spillFinalised($record);

        $line = $this->spillLines()[0];

        self::assertGreaterThan(1048576, strlen($line));
        self::assertSame(FailureSpill::line($record->toArray()), $line);
        self::assertSame($large, $this->decoded($line)['properties']['note']);
    }

    /**
     * A `%` in a value, a key or a code is written as its JSON escape, so the
     * line holds none, and it decodes back to the value.
     *
     * @return void
     */
    public function testALineHoldsNoPercentSign(): void
    {
        $record = $this->finalisedWith(['properties' => ['share' => '100%', '%key%' => '%%s', 'note' => '\u0025 is a percent']]);

        $this->captureLogLines();

        $this->spill()->spillFinalised($record);

        $line = $this->spillLines()[0];

        self::assertStringNotContainsString('%', $line);
        self::assertStringContainsString('"share":"100\u0025"', $line);
        $kept = array_intersect_key($this->decoded($line)['properties'], ['share' => 0, '%key%' => 0, 'note' => 0]);

        self::assertSame(['%key%' => '%%s', 'note' => '\u0025 is a percent', 'share' => '100%'], $kept);
    }

    /**
     * Rows of `[token, rewritten]`: tokens Monolog's `LineFormatter` knows, and
     * whether it rewrites or strips the token in its output when it is left
     * unescaped, even with a format of the message alone.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function providePercentTokens(): iterable
    {
        yield from [
            'the datetime'    => ['%datetime%', true],
            'a context value' => ['%context.x%', true],
            'an extra value'  => ['%extra.y%', true],
            'the message'     => ['%message%', false],
            'the level'       => ['%level_name%', true],
            'the channel'     => ['%channel%', true],
        ];
    }

    /**
     * A value holding a token the documented channel's formatter knows comes
     * back from the file exactly as it was spilled, decodes to the record's
     * envelope, and still verifies. Left unescaped, the same formatter rewrites
     * most of those tokens, which is what this test guards against.
     *
     * @param  string  $token
     * @param  bool  $rewritten
     * @return void
     */
    #[DataProvider('providePercentTokens')]
    public function testAPercentTokenSurvivesTheDocumentedChannel(string $token, bool $rewritten): void
    {
        $this->spillTo(self::SPILL_CHANNEL);

        $record = $this->finalisedWith(['reason' => $token, 'properties' => ['note' => "before {$token} after", $token => 'keyed']]);

        $this->spill()->spillFinalised($record);

        $contents = $this->contentsOf(self::SPILL_CHANNEL);
        $line     = substr($contents, 0, -1);
        $decoded  = (array) json_decode(substr($line, strlen(FailureSpill::MARKER)), false, 512, JSON_THROW_ON_ERROR);

        self::assertSame(FailureSpill::line($record->toArray()) . "\n", $contents);
        self::assertSame(CanonicalEncoder::encode($record->toArray()), CanonicalEncoder::encode($decoded));
        self::assertTrue(app(RecordSigner::class)->verifies($decoded));

        $unescaped = 'before ' . $token . ' after';

        self::assertSame($rewritten, $unescaped . "\n" !== self::documentedFormatter()->format(self::logRecord($unescaped)));
    }

    /**
     * Through the documented channel, each spill is one physical line ending in
     * one line feed, whatever line breaks its values hold.
     *
     * @return void
     */
    public function testADocumentedChannelWritesOnePhysicalLine(): void
    {
        $this->spillTo(self::SPILL_CHANNEL);

        $this->spill()->spillFinalised($this->finalisedWith(['reason' => self::LINE_BREAKS, 'properties' => ['note' => self::LINE_BREAKS]]));
        $this->spill()->spillUnsigned(RecordFactory::withFields(['user_agent' => self::LINE_BREAKS]));

        $lines = explode("\n", $this->contentsOf(self::SPILL_CHANNEL));

        self::assertCount(3, $lines);
        self::assertSame('', $lines[2]);
        self::assertStringStartsWith(FailureSpill::MARKER, $lines[0]);
        self::assertStringStartsWith(FailureSpill::MARKER, $lines[1]);
        self::assertStringNotContainsString("\r", $lines[0] . $lines[1]);
    }

    /**
     * The documented formatter writes the line byte for byte: escapes,
     * backslashes, quotes and Unicode are left as the spill wrote them.
     *
     * @return void
     */
    public function testTheDocumentedFormatterLeavesEscapesAlone(): void
    {
        $this->spillTo(self::SPILL_CHANNEL);

        $record = $this->finalisedWith(['properties' => [
            'controls'  => "nul\0 bell\x07",
            'escapes'   => "tab\there \"quoted\" back\\slash \\n \\r \\u0025",
            'json'      => '{"a":[1,2],"b":{"c":"d"}}',
            'separator' => "line\u{2028}paragraph\u{2029}",
            'unicode'   => 'café, 東京, 🎉',
        ]]);

        $this->spill()->spillFinalised($record);

        $contents = $this->contentsOf(self::SPILL_CHANNEL);

        self::assertSame(FailureSpill::line($record->toArray()) . "\n", $contents);
        self::assertSame($record->toArray()['properties'], $this->decoded(substr($contents, 0, -1))['properties']);
    }

    /**
     * Every parameter that holds the record or its envelope is marked
     * sensitive, so no frame of the spill shows it.
     *
     * @return void
     */
    public function testTheRecordIsMarkedSensitive(): void
    {
        foreach (['spillFinalised' => 'record', 'spillUnsigned' => 'record', 'line' => 'envelope', 'write' => 'envelope'] as $method => $name) {
            $parameter = (new \ReflectionMethod(FailureSpill::class, $method))->getParameters()[0];

            self::assertSame($name, $parameter->getName());
            self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class), "{$method}() does not mark \${$name} sensitive.");
        }
    }

    /**
     * Name the channel the spill writes to: the documented one, or `null` or
     * empty for the default channel.
     *
     * @param  ?string  $spillChannel
     * @return void
     */
    private function spillTo(?string $spillChannel): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.log_channel', $spillChannel);
    }

    /**
     * What the channel's file holds, or nothing when it was never written.
     *
     * @param  string  $channel
     * @return string
     */
    private function contentsOf(string $channel): string
    {
        $file = $this->files[$channel];

        if (!is_file($file)) {
            return '';
        }

        $contents = file_get_contents($file);

        self::assertIsString($contents);

        return $contents;
    }

    /**
     * The spill, as the container builds it.
     *
     * @return \SineMacula\Laravel\AuditLog\Stores\FailureSpill
     */
    private function spill(): FailureSpill
    {
        return app(FailureSpill::class);
    }

    /**
     * A record of the base invoice with the fields given, finalised.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function finalisedWith(array $fields = []): FinalisedRecord
    {
        return $this->finaliser()->finalise(RecordFactory::withFields($fields));
    }

    /**
     * The envelope a spill line holds, decoded to arrays.
     *
     * @param  string  $line
     * @return array<string, array<string, string>|bool|int|string|null>
     */
    private function decoded(string $line): array
    {
        self::assertStringStartsWith(FailureSpill::MARKER, $line);

        /** @var array<string, array<string, string>|bool|int|string|null> */
        return json_decode(substr($line, strlen(FailureSpill::MARKER)), true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * The documented channel's formatter, built as the channel builds it.
     *
     * @return \Monolog\Formatter\LineFormatter
     */
    private static function documentedFormatter(): LineFormatter
    {
        $with = DocumentedSpillChannel::config('unused')['formatter_with'];

        return new LineFormatter($with['format'], allowInlineLineBreaks: $with['allowInlineLineBreaks']);
    }

    /**
     * A record of the message at `critical`, as a channel hands its formatter.
     *
     * @param  string  $message
     * @return \Monolog\LogRecord
     */
    private static function logRecord(string $message): LogRecord
    {
        return new LogRecord(new \DateTimeImmutable, 'testing', Level::Critical, $message);
    }
}
