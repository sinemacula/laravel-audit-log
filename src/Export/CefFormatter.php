<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Export;

use SineMacula\Laravel\AuditLog\Contracts\AuditFormatter;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * Projects a finalised record as one line of the Common Event Format, version
 * 0: `CEF:0|Sine Macula|laravel-audit-log|<record_version>|<event>|<event>|<severity>|<extension>`.
 *
 * Separators and line breaks are escaped, Unicode line separators included, and
 * other control characters cleaned, so no value can end the line or forge a
 * field. The line is a projection, never the integrity artefact.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CefFormatter implements AuditFormatter
{
    /** @var string The device vendor in every header. */
    public const string VENDOR = 'Sine Macula';

    /** @var string The device product in every header. */
    public const string PRODUCT = 'laravel-audit-log';

    /** @var array<string, int> The severity of each outcome. */
    public const array SEVERITIES = ['success' => 3, 'failure' => 6, 'denied' => 7];

    /** @var array<string, string> How a header value's separators are escaped, a carriage return and line feed pair first. */
    private const array HEADER_ESCAPES = ["\r\n" => ' ', "\r" => ' ', "\n" => ' ', "\u{2028}" => ' ', "\u{2029}" => ' ', '\\' => '\\\\', '|' => '\|'];

    /** @var array<string, string> How an extension value's separators are escaped. */
    private const array EXTENSION_ESCAPES = ['\\' => '\\\\', '=' => '\=', "\r" => '\r', "\n" => '\n', "\u{2028}" => '\n', "\u{2029}" => '\n'];

    /**
     * The record as one line of CEF.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function format(#[\SensitiveParameter] FinalisedRecord $record): string
    {
        $captured = $record->record;
        $event    = self::header($captured->event);

        $header = [
            'CEF:0',
            self::header(self::VENDOR),
            self::header(self::PRODUCT),
            self::header((string) $captured->recordVersion),
            $event,
            $event,
            self::severityOf($captured->outcome),
        ];

        return implode('|', $header) . '|' . self::extension($captured);
    }

    /**
     * The extension: each field the record has, in the fixed order, as
     * `key=value` pairs separated by single spaces.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function extension(#[\SensitiveParameter] AuditRecord $record): string
    {
        $fields = array_merge(
            [
                'externalId'               => $record->id,
                'rt'                       => (string) StoredTime::epochMilliseconds($record->occurredAt),
                'act'                      => $record->event,
                'outcome'                  => $record->outcome,
                'src'                      => filter_var($record->ip, FILTER_VALIDATE_IP) === false ? null : $record->ip,
                'requestClientApplication' => $record->userAgent,
            ],
            self::custom(1, 'actor', $record->actorType, $record->actorId),
            self::custom(2, 'subject', $record->subjectType, $record->subjectId),
            self::custom(3, 'tenant', $record->tenantType, $record->tenantId),
        );

        $pairs = [];

        foreach ($fields as $key => $value) {
            if ($value === null) {
                continue;
            }

            $pairs[] = $key . '=' . self::extensionValue($value);
        }

        return implode(' ', $pairs);
    }

    /**
     * The labelled custom string of a reference, as `<type>:<id>`, or nothing
     * when the record has no such reference.
     *
     * @param  int  $number
     * @param  string  $label
     * @param  ?string  $type
     * @param  ?string  $id
     * @return array<string, string>
     */
    private static function custom(int $number, string $label, ?string $type, ?string $id): array
    {
        if ($type === null || $id === null) {
            return [];
        }

        return ['cs' . $number . 'Label' => $label, 'cs' . $number => $type . ':' . $id];
    }

    /**
     * The severity of the outcome.
     *
     * @param  string  $outcome
     * @return int
     *
     * @throws \UnexpectedValueException
     */
    private static function severityOf(string $outcome): int
    {
        return self::SEVERITIES[$outcome] ?? throw new \UnexpectedValueException('A record\'s outcome must be `success`, `failure` or `denied`.');
    }

    /**
     * A header value with its separators escaped and its line breaks made
     * spaces, then cleaned of every other control character.
     *
     * @param  string  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function header(#[\SensitiveParameter] string $value): string
    {
        return TextSanitizer::clean(strtr($value, self::HEADER_ESCAPES));
    }

    /**
     * An extension value with its separators and line breaks escaped, then
     * cleaned of every other control character.
     *
     * @param  string  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function extensionValue(#[\SensitiveParameter] string $value): string
    {
        return TextSanitizer::clean(strtr($value, self::EXTENSION_ESCAPES));
    }
}
