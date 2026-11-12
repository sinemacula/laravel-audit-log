<?php

declare(strict_types = 1);

namespace Tests\Unit\Export;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Export\CefFormatter;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for the CEF formatter: its pinned layout, its escaping, and that
 * no value can forge a field.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CefFormatter::class)]
final class CefFormatterTest extends TestCase
{
    /** @var string The id every record is pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string When every record was recorded. */
    private const string RECORDED_AT = '2026-11-01T12:00:01.654321Z';

    /** @var string An HMAC-SHA256 in lower-case hex. */
    private const string HMAC = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    /** @var string The header of the factory's record. */
    private const string HEADER = 'CEF:0|Sine Macula|laravel-audit-log|1|invoice.approved|invoice.approved|3|';

    /** @var string When the factory's record occurred, in epoch milliseconds. */
    private const string RT = '1793534400123';

    /**
     * The header names the vendor, the product, the record version as the
     * device version, the code as signature and name, and the severity.
     *
     * @return void
     */
    public function testTheHeaderIsPinned(): void
    {
        self::assertStringStartsWith(self::HEADER, self::line(RecordFactory::captured(id: self::ID)));
        self::assertSame('Sine Macula', CefFormatter::VENDOR);
        self::assertSame('laravel-audit-log', CefFormatter::PRODUCT);
    }

    /**
     * The extension holds every field the record has, in the fixed order.
     *
     * @return void
     */
    public function testTheExtensionIsPinnedInOrder(): void
    {
        $expected = self::HEADER . 'externalId=' . self::ID . ' rt=' . self::RT . ' act=invoice.approved outcome=success'
            . ' src=203.0.113.7 requestClientApplication=Mozilla/5.0 cs1Label=actor cs1=user:42'
            . ' cs2Label=subject cs2=invoice:inv_0042 cs3Label=tenant cs3=organisation:org_01';

        self::assertSame($expected, self::line(RecordFactory::captured(id: self::ID)));
    }

    /**
     * `rt` is when the activity occurred in whole milliseconds since the Unix
     * epoch, its microseconds cut, never rounded.
     *
     * @return void
     */
    public function testTheTimeIsEpochMilliseconds(): void
    {
        self::assertStringContainsString(' rt=1793534400999 ', self::line(RecordFactory::withFields(['occurred_at' => '2026-11-01T12:00:00.999000Z'])));
        self::assertStringContainsString(' rt=1793534400000 ', self::line(RecordFactory::withFields(['occurred_at' => '2026-11-01T12:00:00.000999Z'])));
    }

    /**
     * Rows of `[outcome, reason, severity]`: each outcome, its reason and the
     * severity it is given.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: string}>
     */
    public static function provideOutcomes(): iterable
    {
        yield from [
            'a success' => ['success', null, '3'],
            'a failure' => ['failure', 'card_declined', '6'],
            'a denial'  => ['denied', 'insufficient_role', '7'],
        ];
    }

    /**
     * The severity follows the outcome: 3 for a success, 6 for a failure and 7
     * for a denial, and the outcome is in the extension.
     *
     * @param  string  $outcome
     * @param  ?string  $reason
     * @param  string  $severity
     * @return void
     */
    #[DataProvider('provideOutcomes')]
    public function testTheSeverityFollowsTheOutcome(string $outcome, ?string $reason, string $severity): void
    {
        $line = self::line(RecordFactory::withFields(['outcome' => $outcome, 'reason' => $reason]));

        self::assertSame($severity, explode('|', $line)[6]);
        self::assertStringContainsString(' outcome=' . $outcome . ' ', $line);
        self::assertSame(['success' => 3, 'failure' => 6, 'denied' => 7], CefFormatter::SEVERITIES);
    }

    /**
     * An outcome the record model does not know has no severity, and is refused
     * rather than given one.
     *
     * @return void
     */
    public function testRefusesAnUnknownOutcome(): void
    {
        $record = RecordFactory::withFields(['outcome' => 'partial']);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A record\'s outcome must be `success`, `failure` or `denied`.');

        self::line($record);
    }

    /**
     * Rows of `[code, the code in the header, the code in the extension]`: a
     * code holding each header separator.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideHeaderSeparators(): iterable
    {
        yield from [
            'a pipe'                => ['invoice|approved', 'invoice\|approved', 'invoice|approved'],
            'a backslash'           => ['invoice\approved', 'invoice\\\approved', 'invoice\\\approved'],
            'an escaped pipe'       => ['invoice\|approved', 'invoice\\\\\|approved', 'invoice\\\|approved'],
            'a carriage return'     => ["invoice\rapproved", 'invoice approved', 'invoice\rapproved'],
            'a line feed'           => ["invoice\napproved", 'invoice approved', 'invoice\napproved'],
            'both, as one'          => ["invoice\r\napproved", 'invoice approved', 'invoice\r\napproved'],
            'a line separator'      => ["invoice\u{2028}approved", 'invoice approved', 'invoice\napproved'],
            'a paragraph separator' => ["invoice\u{2029}approved", 'invoice approved', 'invoice\napproved'],
            'a forged header field' => ['x|10|act=evil', 'x\|10\|act=evil', 'x|10|act\=evil'],
        ];
    }

    /**
     * A separator in the code is escaped in both header fields and in `act`,
     * and the header keeps its eight fields.
     *
     * @param  string  $code
     * @param  string  $header
     * @param  string  $extension
     * @return void
     */
    #[DataProvider('provideHeaderSeparators')]
    public function testEscapesEachHeaderSeparator(string $code, string $header, string $extension): void
    {
        $line = self::line(RecordFactory::withFields(['event' => $code]));

        self::assertStringStartsWith('CEF:0|Sine Macula|laravel-audit-log|1|' . $header . '|' . $header . '|3|externalId=', $line);
        self::assertStringContainsString(' act=' . $extension . ' outcome=', $line);
        // A pipe preceded by an even number of backslashes separates fields
        $fields = preg_split('/(?<!\\\)(?:\\\\\\\)*\K\|/', strstr($line, '|externalId=', true) ?: '');

        self::assertCount(7, $fields ?: []);
    }

    /**
     * Rows of `[user agent, as the extension writes it]`: a value holding each
     * extension separator, and the pipe, which the extension leaves alone.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideExtensionSeparators(): iterable
    {
        yield from [
            'an equals sign'        => ['a=b', 'a\=b'],
            'a backslash'           => ['a\b', 'a\\\b'],
            'a carriage return'     => ["a\rb", 'a\rb'],
            'a line feed'           => ["a\nb", 'a\nb'],
            'both'                  => ["a\r\nb", 'a\r\nb'],
            'a line separator'      => ["a\u{2028}b", 'a\nb'],
            'a paragraph separator' => ["a\u{2029}b", 'a\nb'],
            'an escaped equals'     => ['a\=b', 'a\\\\\=b'],
            'a pipe, left as it is' => ['a|b', 'a|b'],
        ];
    }

    /**
     * Each extension separator is escaped, a backslash first, so an escape the
     * value holds never reads as one.
     *
     * @param  string  $value
     * @param  string  $escaped
     * @return void
     */
    #[DataProvider('provideExtensionSeparators')]
    public function testEscapesEachExtensionSeparator(string $value, string $escaped): void
    {
        $line = self::line(RecordFactory::withFields(['user_agent' => $value]));

        self::assertStringContainsString(' requestClientApplication=' . $escaped . ' cs1Label=actor ', $line);
    }

    /**
     * Other control characters are cleaned as at capture: a tab becomes a
     * space, and NUL and bidirectional overrides are removed.
     *
     * @return void
     */
    public function testCleansEveryOtherControlCharacter(): void
    {
        $line = self::line(RecordFactory::withFields(['event' => "invoice\tapp\0roved", 'user_agent' => "Mozilla\t5\0.0\u{202E}"]));

        self::assertStringStartsWith('CEF:0|Sine Macula|laravel-audit-log|1|invoice approved|invoice approved|3|', $line);
        self::assertStringContainsString(' requestClientApplication=Mozilla 5.0 ', $line);
    }

    /**
     * Unicode is kept as it is, in the header and the extension: accents, other
     * scripts and emoji.
     *
     * @return void
     */
    public function testKeepsUnicode(): void
    {
        $line = self::line(RecordFactory::withFields(['event' => 'facture.approuvée', 'user_agent' => 'Zoë 日本語 🎉']));

        self::assertStringContainsString('|facture.approuvée|facture.approuvée|', $line);
        self::assertStringContainsString(' requestClientApplication=Zoë 日本語 🎉 ', $line);
    }

    /**
     * A field the record does not have is left out of the extension, key and
     * all, and the rest keep their order.
     *
     * @return void
     */
    public function testOmitsWhatTheRecordHasNot(): void
    {
        $record = RecordFactory::withFields([
            'id'           => self::ID,
            'ip'           => null,
            'user_agent'   => null,
            'actor_type'   => null,
            'actor_id'     => null,
            'subject_type' => null,
            'subject_id'   => null,
            'tenant_type'  => null,
            'tenant_id'    => null,
        ]);

        self::assertSame(self::HEADER . 'externalId=' . self::ID . ' rt=' . self::RT . ' act=invoice.approved outcome=success', self::line($record));
    }

    /**
     * A reference whose type or id alone is set is not written; capture never
     * produces one, but a custom string must name both.
     *
     * @return void
     */
    public function testAReferenceMissingAPartIsOmitted(): void
    {
        $line = self::line(RecordFactory::withFields(['actor_type' => null, 'subject_id' => null]));

        self::assertStringNotContainsString('cs1', $line);
        self::assertStringNotContainsString('cs2', $line);
        self::assertStringEndsWith(' cs3Label=tenant cs3=organisation:org_01', $line);
    }

    /**
     * Rows of `[stored address]`: what an IP mode can store that is not an IP
     * address.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNonAddresses(): iterable
    {
        yield from [
            'a hash'            => ['d03d4735ce37bd96:' . str_repeat('ab', 32)],
            'truncated as text' => ['203.0.113.0/24'],
            'an encrypted form' => ['{"c":"c2VhbGVk","k":"key-1","v":1}'],
        ];
    }

    /**
     * A stored address that is not an IP address, which a mode can store, is no
     * source: `src` is left out rather than given something else.
     *
     * @param  string  $stored
     * @return void
     */
    #[DataProvider('provideNonAddresses')]
    public function testAnAddressThatIsNoAddressIsNoSource(string $stored): void
    {
        $line = self::line(RecordFactory::withFields(['ip' => $stored]));

        self::assertStringNotContainsString('src=', $line);
        self::assertStringContainsString(' outcome=success requestClientApplication=', $line);
    }

    /**
     * An IPv6 address, and a truncated address that is still one, is a source.
     *
     * @return void
     */
    public function testAnyIpAddressIsASource(): void
    {
        self::assertStringContainsString(' src=2001:db8::1 ', self::line(RecordFactory::withFields(['ip' => '2001:db8::1'])));
        self::assertStringContainsString(' src=203.0.113.0 ', self::line(RecordFactory::withFields(['ip' => '203.0.113.0'])));
    }

    /**
     * Each custom string is preceded by its label, and holds its reference as
     * `<type>:<id>`, escaped as any value is.
     *
     * @return void
     */
    public function testACustomStringIsLabelled(): void
    {
        $line = self::line(RecordFactory::withFields(['actor_type' => 'App\Models\User', 'actor_id' => 'a=b']));

        self::assertStringContainsString(' cs1Label=actor cs1=App\\\Models\\\User:a\=b cs2Label=subject cs2=invoice:inv_0042 cs3Label=tenant cs3=', $line);
    }

    /**
     * The line is one physical line whatever any value holds, with no line
     * ending.
     *
     * @return void
     */
    public function testIsOneLine(): void
    {
        $break  = "\r\n\n\r\u{2028}\u{2029}";
        $record = RecordFactory::withFields([
            'event'      => 'invoice' . $break . 'approved',
            'outcome'    => 'denied',
            'reason'     => 'x' . $break,
            'user_agent' => $break,
            'actor_id'   => $break,
            'subject_id' => $break,
            'tenant_id'  => $break,
        ]);

        $line = self::line($record);

        self::assertStringNotContainsString("\r", $line);
        self::assertStringNotContainsString("\n", $line);
    }

    /**
     * The same record gives the same bytes on every call and from every
     * formatter.
     *
     * @return void
     */
    public function testRepeatsByteForByte(): void
    {
        $record = self::finalised(RecordFactory::captured(id: self::ID));

        self::assertSame((new CefFormatter)->format($record), (new CefFormatter)->format($record));
    }

    /**
     * A value written to look like more of the extension stays one value: its
     * equals signs are escaped, so it adds no field.
     *
     * @return void
     */
    public function testAValueCannotForgeAnExtension(): void
    {
        $line = self::line(RecordFactory::withFields(['user_agent' => "x=1 act=evil\u{2028}CEF:0|forged\u{2029}y"]));

        preg_match_all('/(?:^|\s)([A-Za-z0-9]+)=/', substr($line, strlen(self::HEADER)), $keys);

        self::assertStringContainsString(' requestClientApplication=x\=1 act\=evil\nCEF:0|forged\ny ', $line);
        self::assertSame([$line], preg_split('/\R/u', $line));
        self::assertSame(['externalId', 'rt', 'act', 'outcome', 'src', 'requestClientApplication', 'cs1Label', 'cs1', 'cs2Label', 'cs2', 'cs3Label', 'cs3'], $keys[1]);
    }

    /**
     * The record's parameter is marked sensitive, so a stack trace never holds
     * the record.
     *
     * @return void
     */
    public function testTheRecordIsMarkedSensitive(): void
    {
        $parameter = (new \ReflectionMethod(CefFormatter::class, 'format'))->getParameters()[0];

        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * The record finalised and formatted.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return string
     */
    private static function line(AuditRecord $record): string
    {
        return (new CefFormatter)->format(self::finalised($record));
    }

    /**
     * The record finalised, recorded a second after it occurred.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private static function finalised(AuditRecord $record): FinalisedRecord
    {
        return new FinalisedRecord($record, self::RECORDED_AT, 1, 'k1', self::HMAC);
    }
}
