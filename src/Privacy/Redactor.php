<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

/**
 * The one key matcher: which keys of a record hold a secret, and the record's
 * values with the whole value of each such key replaced by the marker.
 *
 * A key longer than `KeyCeiling::MAX_BYTES` is sensitive and is never split, so
 * no key can cost more memory than that bound allows, whatever chose it. Any
 * other key is judged on its tokens, in this order. A key with no tokens is not
 * sensitive. A key that is exactly a survivor is not sensitive. A key whose
 * final token is `id`, `ids` or `at` is not sensitive. A key in which a
 * built-in or configured unit occurs as adjacent tokens is sensitive, and any
 * other key is not. Plurals are units of their own, never stemmed, and
 * `audit-log.redaction.keys` adds units only, so a configured unit passes
 * through the first steps like a built-in and nothing can remove a built-in.
 *
 * This is a heuristic. It cannot find a secret in free text or under an
 * innocuous key, an exemption assumes the key holds non-secret metadata, and an
 * exempt container's scalar values are kept. The remedy for each is an explicit
 * rule on the event's definition.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Redactor
{
    /** @var string What the whole value of a sensitive key becomes. */
    public const string MARKER = '[REDACTED]';

    /** @var list<non-empty-list<string>> The tokens of each key that survives though a unit occurs in it, compared whole. */
    public const array SURVIVORS = [
        ['authorization', 'request'],
        ['tokens', 'valid', 'after'],
        ['cookie', 'consent'],
        ['token', 'type'],
        ['api', 'key', 'type'],
        ['bearer', 'method'],
        ['two', 'factor', 'enabled'],
        ['two', 'factor', 'required'],
        ['two', 'factor', 'method'],
        ['two', 'factor', 'type'],
        ['credential', 'type'],
        ['credential', 'kind'],
    ];

    /** @var list<string> The final tokens that mark a key as naming a secret's identifier or a time, not the secret. */
    public const array EXEMPT_FINAL_TOKENS = ['id', 'ids', 'at'];

    /** @var list<non-empty-list<string>> The built-in units, singular and plural, each as the adjacent tokens that make it sensitive. */
    public const array SENSITIVE_UNITS = [
        ['password'],
        ['passwords'],
        ['passwd'],
        ['passwds'],
        ['passcode'],
        ['passcodes'],
        ['passphrase'],
        ['passphrases'],
        ['pwd'],
        ['pwds'],
        ['secret'],
        ['secrets'],
        ['token'],
        ['tokens'],
        ['otp'],
        ['otps'],
        ['totp'],
        ['totps'],
        ['hotp'],
        ['hotps'],
        ['pin'],
        ['pins'],
        ['credential'],
        ['credentials'],
        ['authorization'],
        ['authorizations'],
        ['cookie'],
        ['cookies'],
        ['bearer'],
        ['bearers'],
        ['jwt'],
        ['jwts'],
        ['cvv'],
        ['cvvs'],
        ['cvc'],
        ['cvcs'],
        ['apikey'],
        ['apikeys'],
        ['privatekey'],
        ['privatekeys'],
        ['secretkey'],
        ['secretkeys'],
        ['accesstoken'],
        ['accesstokens'],
        ['authtoken'],
        ['authtokens'],
        ['refreshtoken'],
        ['refreshtokens'],
        ['clientsecret'],
        ['clientsecrets'],
        ['twofactor'],
        ['twofactors'],
        ['recoverycode'],
        ['recoverycodes'],
        ['cardnumber'],
        ['cardnumbers'],
        ['pass', 'word'],
        ['pass', 'words'],
        ['pass', 'phrase'],
        ['pass', 'phrases'],
        ['auth', 'pw'],
        ['auth', 'pws'],
        ['security', 'code'],
        ['security', 'codes'],
        ['api', 'key'],
        ['api', 'keys'],
        ['private', 'key'],
        ['private', 'keys'],
        ['remember', 'token'],
        ['remember', 'tokens'],
        ['two', 'factor'],
        ['two', 'factors'],
        ['recovery', 'code'],
        ['recovery', 'codes'],
        ['card', 'number'],
        ['card', 'numbers'],
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\RedactionSettings  $settings
     */
    public function __construct(

        /** Where the configured units are read from on every call. */
        private RedactionSettings $settings,
    ) {}

    /**
     * The values with the whole value of every sensitive key, map or list
     * included, replaced by the marker, at any depth and with their order kept.
     * A list's indexes are not keys, so only its elements are walked. A kept
     * key's array is walked and its scalar is kept.
     *
     * The configured units are read first, even for an empty array, so a
     * malformed list fails whatever the record holds. This is a heuristic: an
     * exemption assumes non-secret metadata, an exempt container's scalar
     * values are kept, and the remedy is an explicit rule.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    public function redact(#[\SensitiveParameter] array $values): array
    {
        $index     = $this->index();
        $decisions = [];

        return self::walk($values, $index, $decisions);
    }

    /**
     * Whether the matcher finds a secret under the key.
     *
     * @param  string  $key
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isSensitive(#[\SensitiveParameter] string $key): bool
    {
        return self::isSecret($key, $this->index());
    }

    /**
     * The built-in and configured units, by their first token, so a key is
     * compared only with the units that could begin at each of its tokens.
     *
     * @return array<array-key, non-empty-list<non-empty-list<string>>>
     *
     * @throws \InvalidArgumentException
     */
    private function index(): array
    {
        $index = [];

        foreach (array_merge(self::SENSITIVE_UNITS, $this->settings->keys()) as $unit) {
            $index[$unit[0]][] = $unit;
        }

        return $index;
    }

    /**
     * The values with each sensitive key's value replaced, deciding each
     * distinct key once for the whole call.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  array<array-key, non-empty-list<non-empty-list<string>>>  $index
     * @param  array<array-key, bool>  $decisions
     * @return array<array-key, mixed>
     */
    private static function walk(#[\SensitiveParameter] array $values, array $index, #[\SensitiveParameter] array &$decisions): array
    {
        $isList = array_is_list($values);

        foreach ($values as $key => $value) {
            if (!$isList && ($decisions[$key] ??= self::isSecret((string) $key, $index))) {
                $values[$key] = self::MARKER;
            } elseif (is_array($value)) {
                $values[$key] = self::walk($value, $index, $decisions);
            }
        }

        return $values;
    }

    /**
     * Whether the key is sensitive: past the ceiling without being split, and
     * otherwise as the matcher judges its tokens.
     *
     * @param  string  $key
     * @param  array<array-key, non-empty-list<non-empty-list<string>>>  $index
     * @return bool
     */
    private static function isSecret(#[\SensitiveParameter] string $key, array $index): bool
    {
        return KeyCeiling::isExceededBy($key) || self::matches(KeyTokenizer::tokens($key), $index);
    }

    /**
     * The matcher: whether a key of these tokens is sensitive.
     *
     * @param  list<string>  $tokens
     * @param  array<array-key, non-empty-list<non-empty-list<string>>>  $index
     * @return bool
     */
    private static function matches(#[\SensitiveParameter] array $tokens, array $index): bool
    {
        if ($tokens === [] || self::isExempt($tokens)) {
            return false;
        }

        foreach ($tokens as $position => $token) {
            foreach ($index[$token] ?? [] as $unit) {
                if (self::occursAt($tokens, $position, $unit)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Whether a key of these tokens is exactly a survivor, or ends in a token
     * that exempts it.
     *
     * @param  non-empty-list<string>  $tokens
     * @return bool
     */
    private static function isExempt(#[\SensitiveParameter] array $tokens): bool
    {
        return in_array($tokens, self::SURVIVORS, true)
            || in_array($tokens[array_key_last($tokens)], self::EXEMPT_FINAL_TOKENS, true);
    }

    /**
     * Whether the unit's tokens are the adjacent tokens from the position on.
     *
     * @param  list<string>  $tokens
     * @param  int  $position
     * @param  non-empty-list<string>  $unit
     * @return bool
     */
    private static function occursAt(#[\SensitiveParameter] array $tokens, int $position, array $unit): bool
    {
        foreach ($unit as $offset => $token) {
            if (($tokens[$position + $offset] ?? null) !== $token) {
                return false;
            }
        }

        return true;
    }
}
