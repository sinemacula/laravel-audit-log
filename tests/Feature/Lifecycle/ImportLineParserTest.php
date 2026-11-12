<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLineParser;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use Tests\TestCase;

/**
 * Feature tests for reading a line of the import format.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportLineParser::class)]
final class ImportLineParserTest extends TestCase
{
    /** @var string When every line is read. */
    private const string NOW = '2026-11-02 09:00:00.000000';

    /** @var string This installation's own source. */
    private const string OWN = 'app-eu-1';

    /** @var string The source every line is imported from. */
    private const string SOURCE = 'crm-eu';

    /** @var string The file every source names. */
    private string $path = '';

    /**
     * Freeze the clock, name this installation's source and write the file
     * every source names.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app(ConfigRepository::class)->set('audit-log.source.id', self::OWN);

        $this->path = (string) tempnam(sys_get_temp_dir(), 'import-parser-');
    }

    /**
     * Put the clock back and remove the file.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        if (is_file($this->path)) {
            unlink($this->path);
        }

        parent::tearDown();
    }

    /**
     * A line of every field is read into its import line.
     *
     * @return void
     */
    public function testAFullLineIsRead(): void
    {
        $line = $this->parsed(self::fields());

        self::assertInstanceOf(ImportLine::class, $line);
        self::assertSame(3, $line->number);
        self::assertSame(self::SOURCE, $line->sourceId);
        self::assertSame('eu-west-2', $line->sourceRegion);
        self::assertSame('rec-0042', $line->sourceRecordId);
        self::assertSame('invoice.approved', $line->event);
        self::assertSame('2026-10-01T09:00:00.000001Z', $line->occurredAt);
        self::assertSame(Outcome::FAILURE, $line->outcome);
        self::assertSame('over_limit', $line->reason);
        self::assertSame(['type' => 'user', 'id' => '42'], $line->actor?->toArray());
        self::assertSame(['type' => 'invoice', 'id' => 'inv_0042'], $line->subject?->toArray());
        self::assertSame(['type' => 'user', 'id' => '7'], $line->principal?->toArray());
        self::assertSame(['type' => 'organisation', 'id' => 'org_01'], $line->tenant?->toArray());
        self::assertSame('finance', $line->category);
        self::assertSame('app:ticket-123', $line->correlationId);
        self::assertSame(['amount' => '12.5', 'items' => [1, 2], 'nested' => ['big' => '123456789012345678901234567890']], $line->properties);
        self::assertSame(['route' => 'invoices.approve'], $line->context);
        self::assertSame('http', $line->origin);
        self::assertSame('203.0.113.7', $line->ip);
        self::assertSame(0, $line->dropped);
    }

    /**
     * A line of only the required fields is read, every optional one `null`.
     *
     * @return void
     */
    public function testTheOptionalFieldsMayBeLeftOut(): void
    {
        $line = $this->parsed(array_intersect_key(self::fields(), array_flip(['format', 'source_record_id', 'occurred_at', 'event', 'outcome'])));

        self::assertInstanceOf(ImportLine::class, $line);
        self::assertSame(Outcome::FAILURE, $line->outcome);
        self::assertSame([null, null, null, null, null, null, null, null, null, null, null], [
            $line->reason, $line->actor, $line->subject, $line->principal, $line->tenant, $line->category,
            $line->correlationId, $line->properties, $line->context, $line->origin, $line->ip,
        ]);
    }

    /**
     * Each optional field may be given as `null`.
     *
     * @return void
     */
    public function testEachOptionalFieldMayBeNull(): void
    {
        $fields = array_merge(self::fields(), array_fill_keys(ImportLineParser::OPTIONAL, null));
        $line   = $this->parsed($fields);

        self::assertInstanceOf(ImportLine::class, $line);
        self::assertNull($line->origin);
        self::assertNull($line->properties);
    }

    /**
     * Rows of `[field, value]`: an accepted value of each field.
     *
     * @return iterable<string, array{0: string, 1: array<string, int|string>|int|string}>
     */
    public static function provideAcceptedFields(): iterable
    {
        yield from [
            'a record id of 191 characters' => ['source_record_id', str_repeat('r', 191)],
            'a denial'                      => ['outcome', 'denied'],
            'a reason with every symbol'    => ['reason', 'a.b:c-d_e9'],
            'a reference with a number id'  => ['actor', ['type' => 'user', 'id' => 42]],
            'a category of 64 characters'   => ['category', 'a' . str_repeat('b', 63)],
            'a console origin'              => ['origin', 'console'],
            'a queue origin'                => ['origin', 'queue'],
            'an IPv6 address'               => ['ip', '2001:db8::1'],
            'an IP that is not one'         => ['ip', 'not an address'],
        ];
    }

    /**
     * Each accepted value is read.
     *
     * @param  string  $field
     * @param  array<string, int|string>|int|string  $value
     * @return void
     */
    #[DataProvider('provideAcceptedFields')]
    public function testEachAcceptedValueIsRead(string $field, array|int|string $value): void
    {
        self::assertInstanceOf(ImportLine::class, $this->parsed([...self::fields(), $field => $value]), $field);
    }

    /**
     * Rows of `[field, value, reason]`: a refused value of each field and its
     * rejection.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection}>
     */
    public static function provideRefusedFields(): iterable
    {
        $invalid = ImportRejection::INVALID_FIELD;

        yield from [
            'an empty record id'          => ['source_record_id', '', $invalid],
            'a record id too long'        => ['source_record_id', str_repeat('r', 192), $invalid],
            'a record id with a control'  => ['source_record_id', "rec\x01", $invalid],
            'a number record id'          => ['source_record_id', 42, $invalid],
            'a time without microseconds' => ['occurred_at', '2026-10-01T09:00:00Z', ImportRejection::INVALID_TIME],
            'a time with an offset'       => ['occurred_at', '2026-10-01T09:00:00.000000+01:00', ImportRejection::INVALID_TIME],
            'a time that does not exist'  => ['occurred_at', '2026-02-30T09:00:00.000000Z', ImportRejection::INVALID_TIME],
            'a number time'               => ['occurred_at', 1767254400, ImportRejection::INVALID_TIME],
            'a code of one segment'       => ['event', 'approved', $invalid],
            'an upper-case code'          => ['event', 'Invoice.Approved', $invalid],
            'a number code'               => ['event', 7, $invalid],
            'an unknown outcome'          => ['outcome', 'maybe', $invalid],
            'a number outcome'            => ['outcome', 1, $invalid],
            'a reason of a space'         => ['reason', 'over limit', $invalid],
            'a number reason'             => ['reason', 3, $invalid],
            'a reference of a string'     => ['actor', 'user:42', $invalid],
            'a reference without its id'  => ['subject', ['type' => 'invoice'], $invalid],
            'a reference with a third'    => ['principal', ['type' => 'user', 'id' => '7', 'name' => 'x'], $invalid],
            'a reference of an empty id'  => ['tenant', ['type' => 'organisation', 'id' => ''], $invalid],
            'a reference with a list id'  => ['tenant', ['type' => 'organisation', 'id' => [1]], $invalid],
            'an upper-case category'      => ['category', 'Finance', $invalid],
            'a number category'           => ['category', 5, $invalid],
            'a number correlation'        => ['correlation_id', 12, $invalid],
            'a list of properties'        => ['properties', [1, 2], $invalid],
            'a string of properties'      => ['properties', 'amount', $invalid],
            'a list of context'           => ['context', ['route'], $invalid],
            'an unknown origin'           => ['origin', 'cron', $invalid],
            'a number IP'                 => ['ip', 2130706433, $invalid],
        ];
    }

    /**
     * Each refused value rejects the line for its reason.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $field
     * @param  mixed  $value
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection  $reason
     * @return void
     */
    #[DataProvider('provideRefusedFields')]
    public function testEachRefusedValueRejectsTheLine(string $field, mixed $value, ImportRejection $reason): void
    {
        self::assertSame($reason, $this->parsed([...self::fields(), $field => $value]), $field);
    }

    /**
     * A success with a reason is refused: only a failure or a denial has one.
     *
     * @return void
     */
    public function testASuccessWithAReasonIsRejected(): void
    {
        self::assertSame(ImportRejection::INVALID_FIELD, $this->parsed([...self::fields(), 'outcome' => 'success']));
        self::assertInstanceOf(ImportLine::class, $this->parsed([...self::fields(), 'outcome' => 'success', 'reason' => null]));
    }

    /**
     * Rows of `[text, reason]`: lines that are not of the import format at all.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection}>
     */
    public static function provideUnreadableLines(): iterable
    {
        yield from [
            'not JSON'              => ['{"format": ', ImportRejection::MALFORMED_JSON],
            'a JSON list'           => ['[1, 2]', ImportRejection::MALFORMED_JSON],
            'a JSON string'         => ['"line"', ImportRejection::MALFORMED_JSON],
            'invalid UTF-8'         => ["{\"format\":\"audit-log-import/v1\",\"event\":\"\xC3\"}", ImportRejection::MALFORMED_JSON],
            'too deep'              => [str_repeat('{"a":', 70) . '1' . str_repeat('}', 70), ImportRejection::MALFORMED_JSON],
            'no format'             => ['{"event":"invoice.approved"}', ImportRejection::UNSUPPORTED_FORMAT],
            'a null format'         => ['{"format":null}', ImportRejection::UNSUPPORTED_FORMAT],
            'another format'        => ['{"format":"other/v1"}', ImportRejection::UNSUPPORTED_FORMAT],
            'the export format'     => ['{"format":"audit-log-export/v1"}', ImportRejection::UNSUPPORTED_FORMAT],
            'another version'       => ['{"format":"audit-log-import/v2"}', ImportRejection::UNSUPPORTED_VERSION],
            'an unversioned family' => ['{"format":"audit-log-import/"}', ImportRejection::UNSUPPORTED_VERSION],
        ];
    }

    /**
     * Each unreadable line is rejected for its reason.
     *
     * @param  string  $text
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection  $reason
     * @return void
     */
    #[DataProvider('provideUnreadableLines')]
    public function testAnUnreadableLineIsRejected(string $text, ImportRejection $reason): void
    {
        self::assertSame($reason, $this->parser()->parse(1, $text, $this->source()));
    }

    /**
     * A field the format does not have is `UNKNOWN_FIELD`.
     *
     * @return void
     */
    public function testAnUnknownFieldIsRejected(): void
    {
        self::assertSame(ImportRejection::UNKNOWN_FIELD, $this->parsed([...self::fields(), 'note' => 'x']));
        self::assertSame(ImportRejection::UNKNOWN_FIELD, $this->parsed([...self::fields(), 'source_id' => self::SOURCE]));
        self::assertSame(ImportRejection::UNKNOWN_FIELD, $this->parsed([...self::fields(), 'hmac' => str_repeat('a', 64)]));
    }

    /**
     * Rows of `[field]`: each required field.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRequiredFields(): iterable
    {
        foreach (ImportLineParser::REQUIRED as $field) {
            yield $field => [$field];
        }
    }

    /**
     * Each required field, left out or `null`, is `MISSING_FIELD`.
     *
     * @param  string  $field
     * @return void
     */
    #[DataProvider('provideRequiredFields')]
    public function testAMissingFieldIsRejected(string $field): void
    {
        $fields = self::fields();

        self::assertSame(ImportRejection::MISSING_FIELD, $this->parsed([...$fields, $field => null]));

        unset($fields[$field]);

        self::assertSame(ImportRejection::MISSING_FIELD, $this->parsed($fields));
    }

    /**
     * A time is accepted up to the configured skew after the clock, five
     * minutes by default.
     *
     * @return void
     */
    public function testTheFutureSkewIsTheSetting(): void
    {
        $config = app(ConfigRepository::class);

        self::assertInstanceOf(ImportLine::class, $this->parsed([...self::fields(), 'occurred_at' => '2026-11-02T09:05:00.000000Z']));
        self::assertSame(ImportRejection::FUTURE_TIME, $this->parsed([...self::fields(), 'occurred_at' => '2026-11-02T09:05:00.000001Z']));

        $config->set('audit-log.import.max_skew_seconds', 60);

        self::assertInstanceOf(ImportLine::class, $this->parsed([...self::fields(), 'occurred_at' => '2026-11-02T09:01:00.000000Z']));
        self::assertSame(ImportRejection::FUTURE_TIME, $this->parsed([...self::fields(), 'occurred_at' => '2026-11-02T09:01:00.000001Z']));

        $config->set('audit-log.import.max_skew_seconds', 0);

        self::assertInstanceOf(ImportLine::class, $this->parsed([...self::fields(), 'occurred_at' => '2026-11-02T09:00:00.000000Z']));
        self::assertSame(ImportRejection::FUTURE_TIME, $this->parsed([...self::fields(), 'occurred_at' => '2026-11-02T09:00:00.000001Z']));
    }

    /**
     * A code under the package's reserved prefix is `RESERVED_CODE`.
     *
     * @return void
     */
    public function testAReservedCodeIsRejected(): void
    {
        self::assertSame(ImportRejection::RESERVED_CODE, $this->parsed([...self::fields(), 'event' => 'audit_log.pruned']));
        self::assertSame(ImportRejection::RESERVED_CODE, $this->parsed([...self::fields(), 'event' => 'audit_log.trail_exported']));
        self::assertSame(ImportRejection::RESERVED_CODE, $this->parsed([...self::fields(), 'event' => 'audit_log.Bad']));
        self::assertInstanceOf(ImportLine::class, $this->parsed([...self::fields(), 'event' => 'audit_logs.approved']));
    }

    /**
     * Every envelope-shaped value is removed and counted at any depth.
     *
     * @return void
     */
    public function testEnvelopeShapedValuesAreDroppedAtAnyDepth(): void
    {
        $envelope = ['v' => 1, 'k' => 'subject:user:42:1', 'c' => 'ciphertext'];
        $line     = $this->parsed([...self::fields(),
            'properties' => [
                'secret' => $envelope,
                'kept'   => ['v' => 1, 'k' => 'x', 'c' => 'y', 'd' => 'z'],
                'part'   => ['v' => 1, 'k' => 'x'],
                'deep'   => ['a' => ['b' => ['c' => $envelope, 'd' => 'stays']]],
                'list'   => ['first', $envelope, 'last'],
                'any'    => ['c' => [], 'k' => null, 'v' => 'not a version'],
            ],
            'context' => ['route' => 'invoices.approve', 'shaped' => ['c' => 'x', 'v' => 2, 'k' => 'y']],
        ]);

        self::assertInstanceOf(ImportLine::class, $line);
        self::assertSame([
            'kept' => ['v' => 1, 'k' => 'x', 'c' => 'y', 'd' => 'z'],
            'part' => ['v' => 1, 'k' => 'x'],
            'deep' => ['a' => ['b' => ['d' => 'stays']]],
            'list' => ['first', 'last'],
        ], $line->properties);
        self::assertSame(['route' => 'invoices.approve'], $line->context);
        self::assertSame(5, $line->dropped);

        $whole = $this->parsed([...self::fields(), 'properties' => $envelope, 'context' => $envelope]);

        self::assertInstanceOf(ImportLine::class, $whole);
        self::assertNull($whole->properties);
        self::assertNull($whole->context);
        self::assertSame(2, $whole->dropped);
    }

    /**
     * An IP address that is an envelope's JSON is removed and counted.
     *
     * @return void
     */
    public function testAnEnvelopeShapedIpIsDropped(): void
    {
        $line = $this->parsed([...self::fields(), 'ip' => '{"v":1,"k":"subject:user:42:1","c":"ciphertext"}']);

        self::assertInstanceOf(ImportLine::class, $line);
        self::assertNull($line->ip);
        self::assertSame(1, $line->dropped);

        $padded = $this->parsed([...self::fields(), 'ip' => ' {"c":"x","k":"y","v":1}']);

        self::assertInstanceOf(ImportLine::class, $padded);
        self::assertNull($padded->ip);

        $other = $this->parsed([...self::fields(), 'ip' => '{"v":1,"k":"x"}']);

        self::assertInstanceOf(ImportLine::class, $other);
        self::assertSame('{"v":1,"k":"x"}', $other->ip);
        self::assertSame(0, $other->dropped);
    }

    /**
     * A property key under the reserved `_audit` prefix is refused at any
     * depth.
     *
     * @return void
     */
    public function testAnAuditKeyIsRejected(): void
    {
        self::assertSame(ImportRejection::INVALID_FIELD, $this->parsed([...self::fields(), 'properties' => ['_audit' => ['manifest' => 'x']]]));
        self::assertSame(ImportRejection::INVALID_FIELD, $this->parsed([...self::fields(), 'properties' => ['a' => ['_audit_note' => 'x']]]));
        self::assertSame(ImportRejection::INVALID_FIELD, $this->parsed([...self::fields(), 'properties' => ['list' => [['_audit' => 1]]]]));
        self::assertInstanceOf(ImportLine::class, $this->parsed([...self::fields(), 'properties' => ['audit' => 1, 'x_audit' => 2]]));
        self::assertInstanceOf(ImportLine::class, $this->parsed([...self::fields(), 'context' => ['_audit' => 'route']]));
    }

    /**
     * A line whose source is this installation is rejected `OWN_SOURCE`.
     *
     * @return void
     */
    public function testALineOfThisInstallationIsRejected(): void
    {
        $source = ImportSource::fromFile($this->path, self::OWN);

        self::assertSame(ImportRejection::OWN_SOURCE, $this->parser()->parse(1, (string) json_encode(self::fields()), $source));
    }

    /**
     * The envelope shape is read by its keys alone, as an object or as a map.
     *
     * @return void
     */
    public function testTheEnvelopeShapeIsItsKeysAlone(): void
    {
        self::assertTrue(ImportLineParser::isEnvelopeShaped(['k' => 1, 'c' => 2, 'v' => 3]));
        self::assertTrue(ImportLineParser::isEnvelopeShaped((object) ['v' => null, 'k' => null, 'c' => null]));
        self::assertFalse(ImportLineParser::isEnvelopeShaped(['v' => 1, 'k' => 2]));
        self::assertFalse(ImportLineParser::isEnvelopeShaped(['v' => 1, 'k' => 2, 'c' => 3, 'd' => 4]));
        self::assertFalse(ImportLineParser::isEnvelopeShaped(['v', 'k', 'c']));
        self::assertFalse(ImportLineParser::isEnvelopeShaped(['V' => 1, 'K' => 2, 'C' => 3]));
        self::assertFalse(ImportLineParser::isEnvelopeShaped('{"v":1,"k":"x","c":"y"}'));
        self::assertFalse(ImportLineParser::isEnvelopeShaped(null));
    }

    /**
     * Every field of a full line of the import format.
     *
     * @return array<string, array<string, array<string, list<int>|string>|list<int>|string>|string>
     */
    private static function fields(): array
    {
        return [
            'format'           => 'audit-log-import/v1',
            'source_record_id' => 'rec-0042',
            'occurred_at'      => '2026-10-01T09:00:00.000001Z',
            'event'            => 'invoice.approved',
            'outcome'          => 'failure',
            'reason'           => 'over_limit',
            'actor'            => ['type' => 'user', 'id' => '42'],
            'subject'          => ['type' => 'invoice', 'id' => 'inv_0042'],
            'principal'        => ['type' => 'user', 'id' => '7'],
            'tenant'           => ['type' => 'organisation', 'id' => 'org_01'],
            'category'         => 'finance',
            'correlation_id'   => 'app:ticket-123',
            'properties'       => ['amount' => '__DECIMAL__', 'items' => [1, 2], 'nested' => ['big' => '__BIG__']],
            'context'          => ['route' => 'invoices.approve'],
            'origin'           => 'http',
            'ip'               => '203.0.113.7',
        ];
    }

    /**
     * The fields given, as a line, parsed as line 3 of the import's source.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection|\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private function parsed(array $fields): ImportLine|ImportRejection
    {
        $text = str_replace(['"__DECIMAL__"', '"__BIG__"'], ['12.50', '123456789012345678901234567890'], (string) json_encode($fields));

        return $this->parser()->parse(3, $text, $this->source());
    }

    /**
     * The import's source.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource
     */
    private function source(): ImportSource
    {
        return ImportSource::fromFile($this->path, self::SOURCE, 'eu-west-2');
    }

    /**
     * The parser the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLineParser
     */
    private function parser(): ImportLineParser
    {
        return app(ImportLineParser::class);
    }
}
