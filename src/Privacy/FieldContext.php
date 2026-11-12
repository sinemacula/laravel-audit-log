<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Where a sealed value will be stored and for whom; an envelope is bound to its
 * entry, path and log, and opens nowhere else.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FieldContext
{
    /** @var list<string> The columns a path may start with. */
    public const array COLUMNS = ['properties', 'context', 'ip'];

    /** @var string A lower-case UUID: an entry id. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string A log id: 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit. */
    private const string LOG_ID_PATTERN = '/\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z/';

    /** @var string Refusal for a malformed path; names nothing of it. */
    private const string MALFORMED_PATH = 'A field context\'s path must be a list of `properties`, `context` or `ip`, then map keys and list'
        . ' indexes, each a string or an integer from 0; `ip` stands alone.';

    /** @var non-empty-list<int|string> Where in the entry the value sits: the column, then each map key and list index. */
    public array $path;

    /** @var list<\SineMacula\Laravel\AuditLog\Records\Reference> Every owner the record encrypts for, each once, sorted by type then id, so every key is fetched at once. */
    public array $owners;

    /**
     * Constructor.
     *
     * @param  string  $entryId
     * @param  array<array-key, int|string>  $path
     * @param  string  $logId
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  string  $category
     * @param  array<array-key, \SineMacula\Laravel\AuditLog\Records\Reference>  $owners
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The id of the entry the value belongs to, a lower-case UUID. */
        public string $entryId,

        // Checked into `$this->path`, never repaired
        #[\SensitiveParameter]
        array $path,

        /** The id of the log the entry is signed into. */
        public string $logId,

        /** The record's tenant, or `null` for a tenantless record. */
        public ?Reference $tenant,

        /** The category of the record's definition. */
        public string $category,

        // In any order and repeated freely; deduplicated into `$this->owners`
        #[\SensitiveParameter]
        array $owners,
    ) {
        if (preg_match(self::UUID_PATTERN, $entryId) !== 1) {
            throw new \InvalidArgumentException('A field context\'s entry id must be a lower-case UUID.');
        }

        $this->path = self::checkedPath($path);

        if (preg_match(self::LOG_ID_PATTERN, $logId) !== 1) {
            throw new \InvalidArgumentException('A field context\'s log id must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.');
        }

        if (preg_match(EventDefinition::CATEGORY_PATTERN, $category) !== 1) {
            throw new \InvalidArgumentException('A field context\'s category must be a lower-case letter, then up to 63 lower-case letters, digits or underscores.');
        }

        $this->owners = self::distinctAndSorted($owners);
    }

    /**
     * The path, refused unless it is a list starting with a column, its `ip`
     * standing alone, and its other parts map keys or list indexes.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $path
     * @return non-empty-list<int|string>
     *
     * @throws \InvalidArgumentException
     */
    private static function checkedPath(#[\SensitiveParameter] array $path): array
    {
        if ($path === [] || !array_is_list($path) || !in_array($path[0], self::COLUMNS, true) || ($path[0] === 'ip' && count($path) > 1)) {
            throw new \InvalidArgumentException(self::MALFORMED_PATH);
        }

        $checked = [$path[0]];

        foreach (array_slice($path, 1) as $segment) {
            if (!is_string($segment) && (!is_int($segment) || $segment < 0)) {
                throw new \InvalidArgumentException(self::MALFORMED_PATH);
            }

            $checked[] = $segment;
        }

        return $checked;
    }

    /**
     * The owners, each once, sorted bytewise by type then id; a non-reference
     * is refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $owners
     * @return list<\SineMacula\Laravel\AuditLog\Records\Reference>
     *
     * @throws \InvalidArgumentException
     */
    private static function distinctAndSorted(#[\SensitiveParameter] array $owners): array
    {
        $distinct = [];

        foreach ($owners as $owner) {
            if (!$owner instanceof Reference) {
                throw new \InvalidArgumentException('A field context\'s owners must each be a reference.');
            }

            // No reference holds a NUL, so it separates the parts unambiguously
            $distinct[$owner->type . "\0" . $owner->id] = $owner;
        }

        usort($distinct, static fn (Reference $left, Reference $right): int => strcmp($left->type, $right->type) ?: strcmp($left->id, $right->id));

        return $distinct;
    }
}
