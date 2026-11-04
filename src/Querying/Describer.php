<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Support\Str;
use Illuminate\Translation\Translator;

/**
 * Describes an entry of the trail for a person: the title of its code from the
 * package's translations, with its code, outcome, reason and display properties
 * as the entry holds them.
 *
 * A title is looked up under `audit-log::codes.<code>` in a flat file keyed by
 * the full code, so related codes such as `invoice.approved` and
 * `invoice.approved.twice` never collide. An application adds or overrides
 * titles in `lang/vendor/audit-log/{locale}/codes.php`. Only a non-empty string
 * is a title: it is taken from the locale asked for, else from the fallback
 * locale, else the code itself is the title, so describing never fails for a
 * missing translation. A handler the application set for missing keys is not
 * asked for one. No value is ever replaced into a title, so nothing stored
 * reaches a translated sentence, and a locale that could name another
 * directory, holding a path separator, `..` or a NUL byte, is never looked up.
 *
 * The reason is the entry's, already `null` when its record concealed it, and
 * the properties are the entry's display view: nothing is read again.
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

    /** @var list<string> What a locale never holds if it is to be looked up, as the translator refuses it when setting a locale. */
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
     * The description of the entry, its title in the locale given or, without
     * one, the application's.
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
     * The key's line in the locale alone when it is a non-empty string other
     * than the key, or `null`: for an unsafe locale, a missing line, or a line
     * that is anything else, such as an array of lines.
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
