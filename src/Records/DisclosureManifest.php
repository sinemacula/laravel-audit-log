<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use Random\RandomException;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * A `disclosure` artifact's canonical form, its fresh nonce keeping the digest
 * from being reversed by guessing filters.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DisclosureManifest
{
    /** @var int The version of the canonical form a disclosure is built in. */
    public const int VERSION = 1;

    /** @var list<int> The versions of the canonical form this release reads. */
    public const array SUPPORTED_VERSIONS = [1];

    /** @var int The most entries one disclosure names: the largest page a read returns. */
    public const int MAX_MEMBERS = 500;

    /** @var list<string> The keys of a version 1 disclosure, sorted. */
    private const array KEYS = ['disclosure_version', 'filters', 'members', 'nonce', 'page', 'scope'];

    /** @var int Length of a disclosure's nonce, in bytes. */
    private const int NONCE_BYTES = 32;

    /** @var int How deep a plaintext is decoded. */
    private const int DEPTH = 16;

    /** @var string An entry's id as every engine returns it: a lower-case UUID. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string An entry's HMAC, and a disclosure's nonce: 64 lower-case hexadecimal characters. */
    private const string HEX_PATTERN = '/\A[0-9a-f]{64}\z/';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The manifest of a read's disclosure: its filters, scope, returned entries
     * in order and page position, under a fresh nonce.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $filters
     * @param  ?array<string, mixed>  $scope
     * @param  list<array{0: string, 1: string}>  $members
     * @param  ?array{0: string, 1: string}  $page
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     *
     * @throws \InvalidArgumentException
     */
    public static function of(array $filters, ?array $scope, #[\SensitiveParameter] array $members, ?array $page = null): Manifest
    {
        $failure = self::membersFailure($members) ?? (self::isPage($page) ? null : 'A disclosure\'s page is the instant and the lower-case UUID of the entry it read after.');

        if ($failure !== null) {
            throw new \InvalidArgumentException($failure);
        }

        $canonical = CanonicalEncoder::encode([
            'disclosure_version' => self::VERSION,
            'filters'            => $filters,
            'members'            => $members,
            'nonce'              => self::nonce(),
            'page'               => $page,
            'scope'              => $scope,
        ]);

        if (self::read($canonical) === null) {
            throw new \InvalidArgumentException(sprintf('A disclosure\'s filters and scope must be maps that encode within %d levels.', self::DEPTH));
        }

        return Manifest::ofContent(ArtifactKind::DISCLOSURE, $canonical, count($members));
    }

    /**
     * The count and digest of a plaintext that is exactly a supported
     * disclosure's canonical form, or `null` for any other.
     *
     * @param  string  $plaintext
     * @return ?array{count: int, digest: string}
     */
    public static function read(#[\SensitiveParameter] string $plaintext): ?array
    {
        $decoded = self::decoded($plaintext);

        if (!self::isDisclosure($decoded)) {
            return null;
        }

        try {
            $canonical = CanonicalEncoder::encode($decoded);
        } catch (\UnexpectedValueException) {
            // A value with no canonical form, a float say, is no disclosure
            return null;
        }

        return $canonical === $plaintext ? ['count' => count($decoded['members']), 'digest' => hash('sha256', $plaintext)] : null;
    }

    /**
     * A fresh nonce: 32 random bytes as 64 lower-case hex.
     *
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function nonce(): string
    {
        try {
            return bin2hex(random_bytes(self::NONCE_BYTES));
        } catch (RandomException) {
            throw new \UnexpectedValueException('A disclosure\'s nonce could not be made.');
        }
    }

    /**
     * Why the members are not a disclosure's, or `null` when they are.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $members
     * @return ?string
     */
    private static function membersFailure(#[\SensitiveParameter] array $members): ?string
    {
        if (count($members) > self::MAX_MEMBERS) {
            return sprintf('A disclosure names at most %d entries.', self::MAX_MEMBERS);
        }

        if (!array_is_list($members)) {
            return 'A disclosure\'s members are a list.';
        }

        return self::pairsFailure($members);
    }

    /**
     * Why the listed members are not each an entry's id and HMAC, once, or
     * `null` when they are.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<mixed>  $members
     * @return ?string
     */
    private static function pairsFailure(#[\SensitiveParameter] array $members): ?string
    {
        $seen = [];

        foreach ($members as $member) {
            if (!self::isMember($member)) {
                return 'A disclosure\'s members are each an entry\'s lower-case UUID and its HMAC of 64 lower-case hexadecimal characters.';
            }

            if (isset($seen[$member[0]])) {
                return 'A disclosure names each entry once.';
            }

            $seen[$member[0]] = true;
        }

        return null;
    }

    /**
     * Whether the value is an entry's id and HMAC.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $member
     * @return bool
     *
     * @phpstan-assert-if-true array{0: string, 1: string} $member
     */
    private static function isMember(#[\SensitiveParameter] mixed $member): bool
    {
        if (!is_array($member) || array_keys($member) !== [0, 1] || !is_string($member[0]) || !is_string($member[1])) {
            return false;
        }

        return preg_match(self::UUID_PATTERN, $member[0]) === 1 && preg_match(self::HEX_PATTERN, $member[1]) === 1;
    }

    /**
     * Whether the value is a disclosure's page: `null`, or an instant and a
     * lower-case UUID.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $page
     * @return bool
     */
    private static function isPage(#[\SensitiveParameter] mixed $page): bool
    {
        if ($page === null) {
            return true;
        }

        if (!is_array($page) || array_keys($page) !== [0, 1] || !is_string($page[0]) || !is_string($page[1])) {
            return false;
        }

        return StoredTime::isInstant($page[0]) && preg_match(self::UUID_PATTERN, $page[1]) === 1;
    }

    /**
     * Whether the decoded value holds exactly a supported version's keys, each
     * of its kind.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $decoded
     * @return bool
     *
     * @phpstan-assert-if-true array{disclosure_version: int, filters: array<array-key, mixed>, members: list<array{0: string, 1: string}>, nonce: string, page: mixed, scope: mixed} $decoded
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function isDisclosure(#[\SensitiveParameter] mixed $decoded): bool
    {
        if (!is_array($decoded) || !self::hasExactlyTheKeys($decoded) || !in_array($decoded['disclosure_version'], self::SUPPORTED_VERSIONS, true)) {
            return false;
        }

        $scope = $decoded['scope'];
        $nonce = $decoded['nonce'];

        if (!is_string($nonce) || preg_match(self::HEX_PATTERN, $nonce) !== 1 || !self::isPage($decoded['page'])) {
            return false;
        }

        return self::isMap($decoded['filters']) && ($scope === null || self::isMap($scope)) && self::isMemberList($decoded['members']);
    }

    /**
     * Whether the decoded value is a list of members a disclosure names.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $members
     * @return bool
     *
     * @phpstan-assert-if-true list<array{0: string, 1: string}> $members
     */
    private static function isMemberList(#[\SensitiveParameter] mixed $members): bool
    {
        return is_array($members) && self::membersFailure($members) === null;
    }

    /**
     * Whether the decoded map has exactly a version 1 disclosure's keys.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $decoded
     * @return bool
     */
    private static function hasExactlyTheKeys(#[\SensitiveParameter] array $decoded): bool
    {
        $keys = array_keys($decoded);

        sort($keys);

        return $keys === self::KEYS;
    }

    /**
     * Whether the decoded value is a map: an empty array or one that is not a
     * list.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-assert-if-true array<array-key, mixed> $value
     */
    private static function isMap(#[\SensitiveParameter] mixed $value): bool
    {
        return is_array($value) && ($value === [] || !array_is_list($value));
    }

    /**
     * The plaintext decoded, or `null` when it is not JSON or nests too deep.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $plaintext
     * @return mixed
     */
    private static function decoded(#[\SensitiveParameter] string $plaintext): mixed
    {
        try {
            return json_decode($plaintext, true, self::DEPTH, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
    }
}
