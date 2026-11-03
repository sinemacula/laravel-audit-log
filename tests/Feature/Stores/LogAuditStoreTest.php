<?php

declare(strict_types = 1);

namespace Tests\Feature\Stores;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Log\LogManager;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Monolog\Formatter\LineFormatter;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditFormatter;
use SineMacula\Laravel\AuditLog\Export\CefFormatter;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\ThrowingLogHandler;
use Tests\TestCase;

/**
 * Feature tests for the store that writes each record as a log line: one line
 * at `info` through the formatter, after the marker, with any line break a
 * formatter left escaped, on the channel named; that Monolog never expands the
 * line again; that a failed channel propagates; and that it is neither durable
 * nor joins a transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LogAuditStore::class)]
final class LogAuditStoreTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore;

    /** @var string The channel the store is given. */
    private const string CHANNEL = 'audit';

    /** @var list<string> The log files this test created. */
    private array $files = [];

    /**
     * Give the store's channel and the application's default channel a file
     * each, so nothing a test logs reaches another log.
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

        $config->set('logging.channels.' . self::CHANNEL, ['driver' => 'single', 'path' => $this->temporaryFile(), 'level' => 'debug']);
        $config->set('logging.channels.application', ['driver' => 'single', 'path' => $this->temporaryFile(), 'level' => 'debug']);
        $config->set('logging.default', 'application');
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
     * Each record is one message at `info`: the marker, then exactly what the
     * formatter made of it.
     *
     * @return void
     */
    public function testWritesOneLineThroughTheFormatter(): void
    {
        $record = $this->finalisedWith();

        $this->captureLogLines();

        $this->logStore()->store($record);

        self::assertCount(1, $this->loggedMessages());
        self::assertSame('info', $this->loggedMessages()[0]->level);
        self::assertSame([], $this->loggedMessages()[0]->context);
        self::assertSame([LogAuditStore::MARKER . (new NdjsonFormatter)->format($record)], $this->logStoreLines());
    }

    /**
     * The line starts with the marker, whatever the formatter makes, so even a
     * JSON projection never starts with a brace.
     *
     * @return void
     */
    public function testPrefixesTheMarker(): void
    {
        $this->captureLogLines();

        $this->logStore(self::formatterReturning('[1,2,3]'))->store($this->finalisedWith());
        $this->logStore(self::formatterReturning(''))->store($this->finalisedWith());

        self::assertSame('audit-log:v1 ', LogAuditStore::MARKER);
        self::assertSame(['audit-log:v1 [1,2,3]', 'audit-log:v1 '], $this->logStoreLines());
    }

    /**
     * Rows of `[formatted, line]`: what a formatter that breaks its one-line
     * promise returns, and the line written for it.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideBrokenLines(): iterable
    {
        yield from [
            'a line feed'           => ["one\ntwo", 'audit-log:v1 one\ntwo'],
            'a carriage return'     => ["one\rtwo", 'audit-log:v1 one\rtwo'],
            'a line separator'      => ["one\u{2028}two", 'audit-log:v1 one\u2028two'],
            'a paragraph separator' => ["one\u{2029}two", 'audit-log:v1 one\u2029two'],
            'both, in order'        => ["one\r\ntwo\n", 'audit-log:v1 one\r\ntwo\n'],
            'escapes left as given' => ['one\ntwo', 'audit-log:v1 one\ntwo'],
        ];
    }

    /**
     * A carriage return or a line feed a formatter left in its line is escaped,
     * so the record is still one line.
     *
     * @param  string  $formatted
     * @param  string  $line
     * @return void
     */
    #[DataProvider('provideBrokenLines')]
    public function testEscapesWhatAFormatterLeft(string $formatted, string $line): void
    {
        $this->captureLogLines();

        $this->logStore(self::formatterReturning($formatted))->store($this->finalisedWith());

        self::assertSame([$line], $this->logStoreLines());
        self::assertStringNotContainsString("\n", $this->logStoreLines()[0]);
        self::assertStringNotContainsString("\r", $this->logStoreLines()[0]);
    }

    /**
     * Through a `LineFormatter` that allows inline line breaks, the marked line
     * is written back as it was, one line, its escaped line feeds intact; the
     * same formatter turns them back into real ones in a line that starts with
     * a brace, which is what the marker prevents.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAMarkedLineIsNotReexpandedByMonolog(): void
    {
        $file   = $this->temporaryFile();
        $record = $this->finalisedWith(['reason' => "denied\nby policy", 'properties' => ['note' => "one\r\ntwo"]]);

        app(ConfigRepository::class)->set('logging.channels.' . self::CHANNEL, [
            'driver'         => 'single',
            'path'           => $file,
            'level'          => 'info',
            'formatter'      => LineFormatter::class,
            'formatter_with' => ['format' => "%message%\n", 'allowInlineLineBreaks' => true],
        ]);

        $this->logStore()->store($record);

        $projection = (new NdjsonFormatter)->format($record);

        self::assertSame(LogAuditStore::MARKER . $projection . "\n", file_get_contents($file));

        $formatter = new LineFormatter("%message%\n", allowInlineLineBreaks: true);

        self::assertNotSame($projection . "\n", $formatter->format(new LogRecord(new \DateTimeImmutable, 'testing', Level::Info, $projection)));
    }

    /**
     * Rows of `[a channel's format and inline line breaks]`: a format holding
     * the message alone, each way, and the default a `single` channel uses.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideChannelFormats(): iterable
    {
        yield from [
            'the message, inline breaks off' => [['formatter' => LineFormatter::class, 'formatter_with' => ['format' => "%message%\n", 'allowInlineLineBreaks' => false]]],
            'the message, inline breaks on'  => [['formatter' => LineFormatter::class, 'formatter_with' => ['format' => "%message%\n", 'allowInlineLineBreaks' => true]]],
            'the channel\'s default'         => [[]],
        ];
    }

    /**
     * A record value holding a formatter's token, with a shared log context
     * built to forge a line and a field, leaves one physical line, a CEF line
     * with its own fields and nothing of the shared context.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $format
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideChannelFormats')]
    public function testNeitherAHostileValueNorTheSharedContextForgesALine(array $format): void
    {
        $file = $this->temporaryFile();

        app(ConfigRepository::class)->set('logging.channels.' . self::CHANNEL, ['driver' => 'single', 'path' => $file, 'level' => 'info', ...$format]);

        Log::shareContext(['request_ref' => "abc\nCEF:0|forged|forged|1|forged.event|forged.event|3|externalId=evil act=forged.event", 'user_email' => 'victim@example.com']);

        $this->logStore(new CefFormatter)->store($this->finalisedWith(['subject_id' => 'a%context%']));

        $contents = (string) file_get_contents($file);

        self::assertCount(1, array_filter(explode("\n", $contents), static fn (string $line): bool => $line !== ''));
        self::assertStringNotContainsString('victim@example.com', $contents);
        self::assertStringNotContainsString('forged', $contents);
        self::assertStringContainsString('cs2=invoice:a%25context%', $contents);
    }

    /**
     * In NDJSON a token expanding inside a JSON string would break the JSON, so
     * it is defused and the line still parses to the same keys.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenCannotBreakAnNdjsonLine(): void
    {
        $file = $this->temporaryFile();

        app(ConfigRepository::class)->set('logging.channels.' . self::CHANNEL, [
            'driver'         => 'single',
            'path'           => $file,
            'level'          => 'info',
            'formatter'      => LineFormatter::class,
            'formatter_with' => ['format' => "%message%\n", 'allowInlineLineBreaks' => false],
        ]);

        Log::shareContext(['forged' => 'a"b']);

        $this->logStore()->store($this->finalisedWith(['subject_id' => 'a%context%']));

        $line    = trim((string) file_get_contents($file));
        $decoded = json_decode(substr($line, strlen(LogAuditStore::MARKER)), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);
        self::assertSame('a%25context%', $decoded['subject_id']);
    }

    /**
     * Rows of `[what a formatter left, what is written]`: each token the
     * `LineFormatter` substitutes, a dotted one included, and a percent sign
     * that opens none.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideTokens(): iterable
    {
        yield from [
            'the message'     => ['%message%', '%25message%'],
            'the context'     => ['%context%', '%25context%'],
            'the extra'       => ['%extra%', '%25extra%'],
            'the level'       => ['%level%', '%25level%'],
            'the level name'  => ['%level_name%', '%25level_name%'],
            'the channel'     => ['%channel%', '%25channel%'],
            'the time'        => ['%datetime%', '%25datetime%'],
            'a context key'   => ['%context.user%', '%25context.user%'],
            'an extra key'    => ['%extra.user%', '%25extra.user%'],
            'a plain percent' => ['100% done', '100% done'],
            'no token'        => ['%other%', '%other%'],
        ];
    }

    /**
     * Each token's opening percent is encoded, whatever the formatter, and
     * nothing else is.
     *
     * @param  string  $formatted
     * @param  string  $written
     * @return void
     */
    #[DataProvider('provideTokens')]
    public function testEveryTokenIsDefused(string $formatted, string $written): void
    {
        $this->captureLogLines();

        $this->logStore(self::formatterReturning($formatted))->store($this->finalisedWith());

        self::assertSame([LogAuditStore::MARKER . $written], $this->logStoreLines());
    }

    /**
     * The line goes past Laravel's wrapper, so no `MessageLogged` listener
     * holds it and no shared context joins it.
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

        $this->logStore()->store($this->finalisedWith());

        self::assertSame([], $heard);
        self::assertSame([], $this->loggedMessages()[0]->context);
    }

    /**
     * The lines go to the channel the store was given, and to no other.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testUsesTheNamedChannel(): void
    {
        $named   = $this->temporaryFile();
        $default = $this->temporaryFile();
        $config  = app(ConfigRepository::class);

        $config->set('logging.channels.' . self::CHANNEL, ['driver' => 'single', 'path' => $named, 'level' => 'debug']);
        $config->set('logging.channels.application', ['driver' => 'single', 'path' => $default, 'level' => 'debug']);
        $config->set('logging.default', 'application');

        $this->logStore()->store($this->finalisedWith());

        self::assertStringContainsString('INFO: ' . LogAuditStore::MARKER, (string) file_get_contents($named));
        self::assertFileDoesNotExist($default);
    }

    /**
     * With no channel named, the lines go to the default channel.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testUsesTheDefaultChannelWhenNoneIsNamed(): void
    {
        $default = $this->temporaryFile();
        $config  = app(ConfigRepository::class);

        $config->set('logging.channels.application', ['driver' => 'single', 'path' => $default, 'level' => 'debug']);
        $config->set('logging.default', 'application');

        (new LogAuditStore(app(LogManager::class), new NdjsonFormatter))->store($this->finalisedWith());

        self::assertStringContainsString('INFO: ' . LogAuditStore::MARKER, (string) file_get_contents($default));
    }

    /**
     * A channel that fails propagates its own exception, and nothing is logged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedChannelPropagates(): void
    {
        app(ConfigRepository::class)->set('logging.channels.' . self::CHANNEL, ThrowingLogHandler::channel());

        $this->captureLogLines();

        try {
            $this->logStore()->store($this->finalisedWith());

            self::fail('Expected the channel\'s failure to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The log is unreachable: ' . ThrowingLogHandler::SECRET, $exception->getMessage());
        }

        self::assertSame([], $this->logStoreLines());
    }

    /**
     * A formatter that fails propagates its own exception, and nothing is
     * logged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedFormatterPropagates(): void
    {
        $formatter = new class implements AuditFormatter {
            /**
             * Fail to project the record.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return string
             *
             * @throws \UnexpectedValueException
             */
            #[\Override]
            public function format(#[\SensitiveParameter] FinalisedRecord $record): string
            {
                throw new \UnexpectedValueException('The record cannot be projected.');
            }
        };

        $this->captureLogLines();

        try {
            $this->logStore($formatter)->store($this->finalisedWith());

            self::fail('Expected the formatter\'s failure to propagate.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('The record cannot be projected.', $exception->getMessage());
        }

        self::assertSame([], $this->loggedMessages());
    }

    /**
     * A retried record is written again: a log line cannot be deduplicated.
     *
     * @return void
     */
    public function testARetriedRecordIsWrittenAgain(): void
    {
        $record = $this->finalisedWith();

        $this->captureLogLines();

        $this->logStore()->store($record);
        $this->logStore()->store($record);

        self::assertCount(2, $this->logStoreLines());
        self::assertSame($this->logStoreLines()[0], $this->logStoreLines()[1]);
    }

    /**
     * It never says a return is durable.
     *
     * @return void
     */
    public function testIsNotDurable(): void
    {
        self::assertFalse($this->logStore()->isDurable());
    }

    /**
     * Rows of `[connection]`: the storage connection, another and an empty
     * name.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideConnections(): iterable
    {
        yield from [
            'the storage connection' => [self::CONNECTION],
            'another'                => ['audit'],
            'an empty name'          => [''],
        ];
    }

    /**
     * It joins no transaction, the storage connection's included.
     *
     * @param  string  $connection
     * @return void
     */
    #[DataProvider('provideConnections')]
    public function testParticipatesInNothing(string $connection): void
    {
        self::assertFalse($this->logStore()->participatesIn($connection));
    }

    /**
     * The record is marked sensitive, so a failure of the channel shows no
     * value of it in the store's frame.
     *
     * @return void
     */
    public function testTheRecordIsMarkedSensitive(): void
    {
        $parameter = (new \ReflectionMethod(LogAuditStore::class, 'store'))->getParameters()[0];

        self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * The log store on the test's channel, with the formatter given or the
     * NDJSON one.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\AuditFormatter  $formatter
     * @return \SineMacula\Laravel\AuditLog\Stores\LogAuditStore
     */
    private function logStore(?AuditFormatter $formatter = null): LogAuditStore
    {
        return new LogAuditStore(app(LogManager::class), $formatter ?? new NdjsonFormatter, self::CHANNEL);
    }

    /**
     * A formatter that returns the text given, whatever the record.
     *
     * @param  string  $formatted
     * @return \SineMacula\Laravel\AuditLog\Contracts\AuditFormatter
     */
    private static function formatterReturning(string $formatted): AuditFormatter
    {
        return new readonly class ($formatted) implements AuditFormatter {
            /**
             * Constructor.
             *
             * @param  string  $formatted
             */
            public function __construct(

                /** What every record is projected as. */
                private string $formatted,
            ) {}

            /**
             * The text given.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return string
             */
            #[\Override]
            public function format(#[\SensitiveParameter] FinalisedRecord $record): string
            {
                return $this->formatted;
            }
        };
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
     * A path for a log file that does not exist yet, deleted when the test
     * ends.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function temporaryFile(): string
    {
        $file = sys_get_temp_dir() . '/audit-log-store-' . bin2hex(random_bytes(8)) . '.log';

        $this->files[] = $file;

        return $file;
    }
}
