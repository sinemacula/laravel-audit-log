<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

/**
 * The one key matcher, replacing the whole value of each secret-named key with
 * the marker; a heuristic, so an explicit rule covers what it misses.
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
     * The values with every sensitive key's whole value replaced by the marker,
     * at any depth; configured units are read first so a malformed list fails
     * any record.
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
     * Whether the key is sensitive: past the ceiling, unsplit, or as its tokens
     * match.
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
