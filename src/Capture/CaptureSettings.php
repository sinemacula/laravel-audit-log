<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Support\MachineCode;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * The settings under `audit-log.capture.`, validated on every read; a malformed
 * value fails naming the key, never the value.
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

    /** @var string Pattern of a credential key. */
    public const string IDENTIFIER_KEY_PATTERN = '/\A[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\z/';

    /** @var int Longest ability name a list may hold, in bytes. */
    public const int ABILITY_MAX_BYTES = 191;

    /** @var string Prefix of every capture setting's key. */
    private const string PREFIX = 'audit-log.capture.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each numeric setting. */
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
     * The guards whose authentication events are not recorded, or `['*']` for
     * every guard.
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
     * Whether an authentication event under the guard is not recorded; a `null`
     * guard is excluded only by `['*']`.
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
     * The key of the credential a failed sign-in is read for, `email` by
     * default.
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
     * Whether Gate denials are recorded; off by default.
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
     * ability.
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
     * Whether a denial of the ability is recorded, comparing ability names
     * exactly.
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
     * The denial codes kept as a reason; none by default.
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
     * The guard name, refused unless it is clean text of 1 to 64 characters.
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
     * The abilities, refused with the message unless each is clean text of 1 to
     * 191 bytes.
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
     * The reason code, refused without naming it unless it is machine-readable.
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
