<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Support\Str;
use Illuminate\Translation\Translator;

/**
 * Describes an entry for a person, titled from `audit-log::codes.<code>` in the
 * locale, else the fallback locale, else the code itself.
 *
 * The file is flat, keyed by full code, so `invoice.approved` and
 * `invoice.approved.twice` never collide. No stored value is put into a title.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Describer
{
    /** @var string The namespace the package's translations are loaded under. */
    public const string NAMESPACE = 'audit-log';

    /** @var string The translation group holding the codes' titles. */
    public const string GROUP = 'codes';

    /** @var list<string> Locale fragments that could name another directory. */
    private const array UNSAFE_LOCALE = ['/', '\\', '..', "\0"];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Translation\Translator  $translator
     */
    public function __construct(

        /** The translator the titles are read through. */
        private Translator $translator,
    ) {}

    /**
     * The description of the entry in the locale, or the application's.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailEntry  $entry
     * @param  ?string  $locale
     * @return \SineMacula\Laravel\AuditLog\Querying\Description
     */
    public function describe(#[\SensitiveParameter] TrailEntry $entry, ?string $locale = null): Description
    {
        return new Description(
            title: $this->title($entry->event, $locale ?? $this->translator->getLocale()),
            code: $entry->event,
            outcome: $entry->outcome,
            reason: $entry->reason,
            properties: $entry->properties,
        );
    }

    /**
     * The code's title in the locale, else in the fallback locale, else the
     * code itself.
     *
     * @param  string  $code
     * @param  string  $locale
     * @return string
     */
    private function title(string $code, string $locale): string
    {
        $key = self::NAMESPACE . '::' . self::GROUP . '.' . $code;

        foreach ([$locale, $this->translator->getFallback()] as $candidate) {
            $line = $this->line($key, $candidate);

            if ($line !== null) {
                return $line;
            }
        }

        return $code;
    }

    /**
     * The key's line in the locale alone when it is a non-empty string, without
     * asking the application's missing-key handler, or `null`.
     *
     * @param  string  $key
     * @param  string  $locale
     * @return ?string
     */
    private function line(string $key, string $locale): ?string
    {
        if (Str::contains($locale, self::UNSAFE_LOCALE) || !$this->translator->has($key, $locale, false)) {
            return null;
        }

        $line = $this->translator->get($key, [], $locale, false);

        return is_string($line) && $line !== '' && $line !== $key ? $line : null;
    }
}
