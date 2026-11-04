<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IpMode;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * What a record keeps of the client's IP address, under the configured mode:
 * the canonical form, its network, a keyed hash, nothing, or an envelope under
 * the actor's key.
 *
 * Every mode starts from the canonical form, in which an IPv4-mapped address is
 * its IPv4 address, so one client has one form, one hash and one network. An
 * address that is not valid, whatever a contributor filled, is stored in no
 * mode, not even in full, and is diagnosed without its value, so it never
 * reaches the column or a report and never costs the record. An encrypted
 * address is sealed as the typed plaintext of the canonical form, its JSON
 * string, for the path `["ip"]`, and is stored as the envelope's canonical
 * JSON. When there is no actor, no key, a failed encrypter or more JSON than
 * the column holds, it is dropped and diagnosed, never truncated. The `drop`
 * mode is configuration rather than loss, so dropping a valid address adds
 * nothing to the diagnostics.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IpMinimiser
{
    /** @var int Most bytes the column holds, and so the most an encrypted address may encode to. */
    public const int COLUMN_BYTES = 255;

    /** @var string The column an address is stored in, the one segment of the path it is sealed at. */
    private const string COLUMN = 'ip';

    /** @var string The diagnostic path of an address that was not stored. */
    private const string DIAGNOSTIC_PATH = '$ip';

    /** @var string The two bytes `2002::/16` begins with, which a 6to4 address carries before its client's IPv4 address. */
    private const string SIX_TO_FOUR_PREFIX = "\x20\x02";

    /** @var string The twelve bytes `::ffff:0:0/96` begins with, which an IPv4-mapped address carries before its IPv4 address. */
    private const string MAPPED_PREFIX = "\0\0\0\0\0\0\0\0\0\0\xff\xff";

    /** @var int How many bytes an IPv4 address holds. */
    private const int IPV4_BYTES = 4;

    /** @var int How many bytes of an IPv4 address its /24 keeps. */
    private const int IPV4_NETWORK_BYTES = 3;

    /** @var int How many bytes of an IPv6 address its /48 keeps. */
    private const int IPV6_NETWORK_BYTES = 6;

    /** @var int How many bytes of a 6to4 address its /40 keeps: the prefix, and the /24 of the client's IPv4 address. */
    private const int SIX_TO_FOUR_NETWORK_BYTES = 5;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\RedactionSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher  $hasher
     */
    public function __construct(

        /** Where the mode is read from on every call. */
        private RedactionSettings $settings,

        /** What hashes an address in the `hash` mode. */
        private IdentifierHasher $hasher,
    ) {}

    /**
     * What the record stores of the address, or `null` when it stores nothing.
     * The mode is read first, so a malformed mode fails even a record with no
     * address. No address is not a loss and adds nothing to the log; an invalid
     * one adds its path in every mode.
     *
     * @param  ?string  $ip
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer  $sealer
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @param  \SineMacula\Laravel\AuditLog\Privacy\SealingScope  $scope
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \UnexpectedValueException
     */
    public function minimise(
        #[\SensitiveParameter]
        ?string $ip,
        #[\SensitiveParameter]
        ?Reference $actor,
        EnvelopeSealer $sealer,
        OmissionLog $omissions,
        SealingScope $scope,
    ): ?string {
        $mode = $this->settings->ipMode();

        if ($ip === null) {
            return null;
        }

        $canonical = self::canonical($ip);

        if ($canonical === null) {
            $omissions->add(self::DIAGNOSTIC_PATH);

            return null;
        }

        return match ($mode) {
            IpMode::FULL     => $canonical,
            IpMode::TRUNCATE => self::truncated($canonical),
            IpMode::HASH     => $this->hasher->ip($canonical),
            IpMode::DROP     => null,
            IpMode::ENCRYPT  => self::encrypted($canonical, $actor, $sealer, $omissions, $scope),
        };
    }

    /**
     * The address in its one canonical form, an IPv4-mapped address as its IPv4
     * address, or `null` when it is not a valid address. The address is
     * validated before it is parsed, because `inet_pton()` warns on anything
     * invalid.
     *
     * @param  string  $ip
     * @return ?string
     */
    public static function canonical(#[\SensitiveParameter] string $ip): ?string
    {
        $packed = filter_var($ip, FILTER_VALIDATE_IP) === false ? false : inet_pton($ip);

        if ($packed === false) {
            return null;
        }

        return (string) inet_ntop(str_starts_with($packed, self::MAPPED_PREFIX) ? substr($packed, strlen(self::MAPPED_PREFIX)) : $packed);
    }

    /**
     * The canonical address's network, with the rest of its bytes zeroed: a /24
     * for IPv4, a /40 for 6to4, whose /48 would keep the client's whole IPv4
     * address, and a /48 for any other IPv6 address.
     *
     * @param  string  $canonicalIp
     * @return string
     */
    private static function truncated(#[\SensitiveParameter] string $canonicalIp): string
    {
        $packed  = (string) inet_pton($canonicalIp);
        $network = match (true) {
            strlen($packed) === self::IPV4_BYTES               => self::IPV4_NETWORK_BYTES,
            str_starts_with($packed, self::SIX_TO_FOUR_PREFIX) => self::SIX_TO_FOUR_NETWORK_BYTES,
            default                                            => self::IPV6_NETWORK_BYTES,
        };

        return (string) inet_ntop(str_pad(substr($packed, 0, $network), strlen($packed), "\0"));
    }

    /**
     * The canonical JSON of the canonical address's envelope under the actor's
     * key, sealed as its JSON string for the path `["ip"]`, or `null` with its
     * path added to the log when there is no actor, no envelope, or more JSON
     * than the column holds. It is never truncated, since a cut envelope could
     * not be decrypted.
     *
     * @param  string  $canonicalIp
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer  $sealer
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @param  \SineMacula\Laravel\AuditLog\Privacy\SealingScope  $scope
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \UnexpectedValueException
     */
    private static function encrypted(
        #[\SensitiveParameter]
        string $canonicalIp,
        #[\SensitiveParameter]
        ?Reference $actor,
        EnvelopeSealer $sealer,
        OmissionLog $omissions,
        SealingScope $scope,
    ): ?string {
        // An address is far shorter than the limit, so its typed plaintext is
        // always its whole JSON string
        $envelope = $actor    === null ? null : $sealer->seal($actor, (string) TypedPlaintext::encode($canonicalIp), $scope->at([self::COLUMN]));
        $encoded  = $envelope === null ? null : CanonicalEncoder::encode($envelope);

        if ($encoded === null || strlen($encoded) > self::COLUMN_BYTES) {
            $omissions->add(self::DIAGNOSTIC_PATH);

            return null;
        }

        return $encoded;
    }
}
