<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * The settings under `audit-log.actor.` and `audit-log.context.`, validated on
 * every read; a malformed value fails naming the key, never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ContextSettings
{
    /** @var string The guards' full key. */
    private const string GUARDS = 'audit-log.actor.guards';

    /** @var string The full key of the flag trusting an inbound request id. */
    private const string TRUST_REQUEST_ID = 'audit-log.context.trust_request_id';

    /** @var string The full key of the request id's header name. */
    private const string REQUEST_ID_HEADER = 'audit-log.context.request_id_header';

    /** @var string The full key of the flag trusting an inbound `traceparent`. */
    private const string TRUST_TRACEPARENT = 'audit-log.context.trust_traceparent';

    /** @var string The request id's header when none is configured. */
    private const string DEFAULT_REQUEST_ID_HEADER = 'X-Request-Id';

    /** @var int Longest guard name, in characters: the `guard` column. */
    private const int GUARD_MAX_CHARACTERS = 64;

    /** @var string Pattern of a header name: an RFC 9110 token of 1 to 64 characters. */
    private const string HEADER_PATTERN = '/\A[!#$%&\'*+.^_`|~0-9A-Za-z-]{1,64}\z/';

    /** @var string Why anything but `null` or a list of guard names is refused. */
    private const string MALFORMED_GUARDS = '`audit-log.actor.guards` must be null, or a list of guard names of 1 to 64 characters.';

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
     * The names of the guards the actor is read from, in order, or `null` for
     * the default guard.
     *
     * @return ?non-empty-list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function guards(): ?array
    {
        $guards = $this->config->get(self::GUARDS);

        if ($guards === null) {
            return null;
        }

        if (!is_array($guards) || $guards === [] || !array_is_list($guards)) {
            throw new \InvalidArgumentException(self::MALFORMED_GUARDS);
        }

        $names = [];

        foreach ($guards as $guard) {
            $names[] = self::guardName($guard);
        }

        return $names;
    }

    /**
     * Whether an inbound request id from a trusted proxy is believed.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function trustsRequestId(): bool
    {
        return $this->isOn(self::TRUST_REQUEST_ID);
    }

    /**
     * The name of the header an inbound request id comes under.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function requestIdHeader(): string
    {
        $header = $this->config->get(self::REQUEST_ID_HEADER, self::DEFAULT_REQUEST_ID_HEADER);

        if (!is_string($header) || preg_match(self::HEADER_PATTERN, $header) !== 1) {
            throw new \InvalidArgumentException(sprintf('`%s` must be a header name of 1 to 64 characters.', self::REQUEST_ID_HEADER));
        }

        return $header;
    }

    /**
     * Whether an inbound `traceparent` from a trusted proxy is believed.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function trustsTraceparent(): bool
    {
        return $this->isOn(self::TRUST_TRACEPARENT);
    }

    /**
     * Read every context setting, failing on the first malformed one.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->guards();
        $this->trustsRequestId();
        $this->requestIdHeader();
        $this->trustsTraceparent();
    }

    /**
     * Whether the flag under the key is on: it must be a real boolean, and a
     * missing key is off.
     *
     * @param  string  $key
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isOn(string $key): bool
    {
        $flag = $this->config->get($key, false);

        if (!is_bool($flag)) {
            throw new \InvalidArgumentException(sprintf('`%s` must be true or false.', $key));
        }

        return $flag;
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
            throw new \InvalidArgumentException(self::MALFORMED_GUARDS);
        }

        return $guard;
    }
}
