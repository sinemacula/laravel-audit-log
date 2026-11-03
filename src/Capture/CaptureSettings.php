<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Support\MachineCode;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * The capture settings, read from configuration on every call and validated as
 * they are read: the guards whose authentication events are not recorded
 * (`audit-log.capture.laravel.except_guards`), the one credential a failed
 * sign-in is read for (`audit-log.capture.laravel.identifier_key`), whether
 * Gate denials are recorded (`audit-log.capture.gate.enabled`), which abilities
 * (`audit-log.capture.gate.only_abilities` and
 * `audit-log.capture.gate.except_abilities`), the denial codes kept as a reason
 * (`audit-log.capture.gate.reason_codes`), and the bounds of a bulk operation's
 * manifest (`audit-log.capture.bulk.max_members` and
 * `audit-log.capture.bulk.max_bytes`).
 *
 * A missing setting takes its default; a `null` set explicitly is malformed,
 * except for `only_abilities`, whose default it is. A flag is a real boolean,
 * so a truthy string never turns capture on. A number is an integer, or the
 * canonical digit string an environment line gives, within its range. A name or
 * an ability is compared exactly, never cleaned or trimmed, and one that is not
 * already clean text is refused. Every malformed value fails closed with an
 * `InvalidArgumentException` naming the key and never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CaptureSettings
{
    /** @var string The only member of `except_guards` that excludes every guard. */
    public const string ALL_GUARDS = '*';

    /** @var int Longest guard name, in characters: the `guard` column. */
    public const int GUARD_MAX_CHARACTERS = 64;

    /** @var string Pattern of a credential key: 1 to 64 letters, digits, underscores, dots or hyphens, starting with a letter, a digit or an underscore. */
    public const string IDENTIFIER_KEY_PATTERN = '/\A[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\z/';

    /** @var int Longest ability name a list may hold, in bytes. */
    public const int ABILITY_MAX_BYTES = 191;

    /** @var string Prefix of every capture setting's key. */
    private const string PREFIX = 'audit-log.capture.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each numeric setting, by its key under the prefix. */
    private const array NUMBERS = [
        'bulk.max_members' => [100000, 1, 1000000],
        'bulk.max_bytes'   => [4194304, 65536, 8388608],
    ];

    /** @var string The credential key when none is configured. */
    private const string DEFAULT_IDENTIFIER_KEY = 'email';

    /** @var string Why anything but a list of guard names, or the wildcard alone, is refused. */
    private const string MALFORMED_EXCEPT_GUARDS = '`audit-log.capture.laravel.except_guards` must be a list of guard names of 1 to 64 characters, or `[\'*\']`.';

    /** @var string Why a credential key outside its grammar is refused. */
    private const string MALFORMED_IDENTIFIER_KEY = '`audit-log.capture.laravel.identifier_key` must be 1 to 64 letters, digits, underscores, dots or hyphens,'
        . ' starting with a letter, a digit or an underscore.';

    /** @var string Why anything but a list of machine-readable codes is refused as the reason codes. */
    private const string MALFORMED_REASON_CODES = '`audit-log.capture.gate.reason_codes` must be a list of machine-readable codes of 1 to 64 characters:'
        . ' lower-case letters, digits, `_`, `.`, `:` or `-`, starting with a letter or a digit.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The guards whose authentication events are not recorded: none unless
     * configured, a list of names, or `['*']` for every guard.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function exceptGuards(): array
    {
        $guards = $this->config->get(self::PREFIX . 'laravel.except_guards', []);

        if (!is_array($guards) || !array_is_list($guards)) {
            throw new \InvalidArgumentException(self::MALFORMED_EXCEPT_GUARDS);
        }

        $names = [];

        foreach ($guards as $guard) {
            $names[] = self::guardName($guard);
        }

        if (in_array(self::ALL_GUARDS, $names, true) && $names !== [self::ALL_GUARDS]) {
            throw new \InvalidArgumentException(self::MALFORMED_EXCEPT_GUARDS);
        }

        return $names;
    }

    /**
     * Whether an authentication event under the guard is not recorded: every
     * one is under `['*']`; otherwise one under a listed guard is, and one with
     * no guard is not.
     *
     * @param  ?string  $guard
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function excludesGuard(?string $guard): bool
    {
        $guards = $this->exceptGuards();

        if ($guards === [self::ALL_GUARDS]) {
            return true;
        }

        return $guard !== null && in_array($guard, $guards, true);
    }

    /**
     * The key of the one credential a failed sign-in is read for: `email`
     * unless configured otherwise.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function identifierKey(): string
    {
        $key = $this->config->get(self::PREFIX . 'laravel.identifier_key', self::DEFAULT_IDENTIFIER_KEY);

        if (!is_string($key) || preg_match(self::IDENTIFIER_KEY_PATTERN, $key) !== 1) {
            throw new \InvalidArgumentException(self::MALFORMED_IDENTIFIER_KEY);
        }

        return $key;
    }

    /**
     * Whether Gate denials are recorded: off unless turned on with a real
     * boolean.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isGateEnabled(): bool
    {
        $enabled = $this->config->get(self::PREFIX . 'gate.enabled', false);

        if (!is_bool($enabled)) {
            throw new \InvalidArgumentException('`audit-log.capture.gate.enabled` must be true or false.');
        }

        return $enabled;
    }

    /**
     * The only abilities whose denials are recorded, or `null` for every
     * ability; a list is never empty.
     *
     * @return ?non-empty-list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function onlyAbilities(): ?array
    {
        $abilities = $this->config->get(self::PREFIX . 'gate.only_abilities');

        if ($abilities === null) {
            return null;
        }

        $message   = sprintf('`audit-log.capture.gate.only_abilities` must be null, or a non-empty list of abilities of 1 to %d bytes.', self::ABILITY_MAX_BYTES);
        $abilities = self::abilities($abilities, $message);

        if ($abilities === []) {
            throw new \InvalidArgumentException($message);
        }

        return $abilities;
    }

    /**
     * The abilities whose denials are never recorded: none unless configured.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function exceptAbilities(): array
    {
        $message = sprintf('`audit-log.capture.gate.except_abilities` must be a list of abilities of 1 to %d bytes.', self::ABILITY_MAX_BYTES);

        return self::abilities($this->config->get(self::PREFIX . 'gate.except_abilities', []), $message);
    }

    /**
     * Whether a denial of the ability is recorded: it is not one of the
     * excepted abilities, and it is one of the only abilities when they are a
     * list. The ability is compared exactly as the Gate gave it, so one that
     * differs in case or whitespace is another ability.
     *
     * @param  string  $ability
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function selectsAbility(string $ability): bool
    {
        if (in_array($ability, $this->exceptAbilities(), true)) {
            return false;
        }

        $only = $this->onlyAbilities();

        return $only === null || in_array($ability, $only, true);
    }

    /**
     * The codes of a denial that are kept as its reason: none unless
     * configured, each a machine-readable code.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function reasonCodes(): array
    {
        $codes = $this->config->get(self::PREFIX . 'gate.reason_codes', []);

        if (!is_array($codes) || !array_is_list($codes)) {
            throw new \InvalidArgumentException(self::MALFORMED_REASON_CODES);
        }

        $kept = [];

        foreach ($codes as $code) {
            $kept[] = self::reasonCode($code);
        }

        return $kept;
    }

    /**
     * The most subjects a bulk operation's manifest holds, from 1 to 1000000.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function bulkMaxMembers(): int
    {
        return $this->number('bulk.max_members');
    }

    /**
     * The most bytes a bulk operation's manifest may encode to, from 65536 to
     * 8388608.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function bulkMaxBytes(): int
    {
        return $this->number('bulk.max_bytes');
    }

    /**
     * Read every capture setting, failing on the first malformed one.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->exceptGuards();
        $this->identifierKey();
        $this->isGateEnabled();
        $this->onlyAbilities();
        $this->exceptAbilities();
        $this->reasonCodes();
        $this->bulkMaxMembers();
        $this->bulkMaxBytes();
    }

    /**
     * The numeric setting under the key, within its range.
     *
     * @param  key-of<self::NUMBERS>  $setting
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function number(string $setting): int
    {
        [$default, $least, $most] = self::NUMBERS[$setting];

        $key = self::PREFIX . $setting;

        return IntegerSetting::from('`' . $key . '`', $this->config->get($key, $default), $least, $most);
    }

    /**
     * The guard name, refused unless it is a string of 1 to 64 characters and
     * already clean text.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $guard
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function guardName(mixed $guard): string
    {
        if (!is_string($guard) || $guard === '' || mb_strlen($guard, 'UTF-8') > self::GUARD_MAX_CHARACTERS || !TextSanitizer::isClean($guard)) {
            throw new \InvalidArgumentException(self::MALFORMED_EXCEPT_GUARDS);
        }

        return $guard;
    }

    /**
     * The list of abilities, refused with the message unless it is a list whose
     * every member is a string of 1 to 191 bytes and already clean text.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $abilities
     * @param  string  $message
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private static function abilities(mixed $abilities, string $message): array
    {
        if (!is_array($abilities) || !array_is_list($abilities)) {
            throw new \InvalidArgumentException($message);
        }

        $names = [];

        foreach ($abilities as $ability) {

            if (!is_string($ability) || $ability === '' || strlen($ability) > self::ABILITY_MAX_BYTES || !TextSanitizer::isClean($ability)) {
                throw new \InvalidArgumentException($message);
            }

            $names[] = $ability;
        }

        return $names;
    }

    /**
     * The reason code, refused unless it is a machine-readable code; the
     * refusal names the setting, never the code.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $code
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function reasonCode(mixed $code): string
    {
        if (!is_string($code)) {
            throw new \InvalidArgumentException(self::MALFORMED_REASON_CODES);
        }

        try {
            return MachineCode::of($code, 'A reason');
        } catch (\InvalidArgumentException) {
            throw new \InvalidArgumentException(self::MALFORMED_REASON_CODES);
        }
    }
}
