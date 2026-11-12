<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use Tests\Concerns\ReadsTheDocumentation;

/**
 * A drift guard for the privacy note and every document's claims about personal
 * data and erasure: it catches an omission or a rename, not wrong prose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class PrivacyDocumentationTest extends TestCase
{
    use ReadsTheDocumentation;

    /** @var string The privacy note, from the repository's root. */
    private const string PRIVACY_NOTE = '/docs/design/privacy.md';

    /** @var list<string> The privacy note's sections, in order: the standard ones around its own. */
    private const array SECTIONS = [
        'Purpose',
        'Invariants',
        'Success Path',
        'Failure / Edge Cases',
        'Keys',
        'Encryption',
        'Key Uses',
        'Reading',
        'Erasure',
        'Restores',
        'What Is Not Erased',
        'Stores And What They Hold',
        'Seams Left',
        'Implementation Anchors',
        'Authoritative Tests',
        'Change Triggers',
    ];

    /** @var string The two guarantees, stated apart: what credentials can do to keys, and what the evidence makes detectable. */
    private const string GUARANTEES = 'Database credentials can still destroy keys, key uses and markers; the package\'s cryptographic evidence '
        . 'makes unauthorised destruction, substitution or restoration detectable, never impossible.';

    /** @var string What a key unit is, and why. */
    private const string UNITS = 'A key unit is the owner, the record\'s tenant and the definition\'s category, '
        . 'so materially different obligations never share a key';

    /** @var string What the reveal grant reveals, and what it is not. */
    private const string REVEAL_SCOPE = 'The grant reveals every encrypted field of every entry the scope sees, whoever owns it, '
        . 'and is not an owner-specific projection';

    /** @var string The section that inventories every store. */
    private const string INVENTORY = 'Stores And What They Hold';

    /** @var string Pattern of a claim that a store, a record or a value holds no personal data. */
    private const string NO_PERSONAL_DATA = '/\b(?:holds?|holding|contains?|containing|carr(?:y|ies|ying)|stores?|storing|keeps?|keeping)\s+no\s+personal\s+data\b'
        . '|\b(?:is|are|be)\s+not\s+personal\s+data\b'
        . '|\bno\s+personal\s+data\s+(?:is|are)\s+(?:held|stored|kept|recorded)\b'
        . '|\bfree\s+of\s+(?:[\w-]+\s+(?:or|and)\s+(?:of\s+)?)?personal\s+data\b'
        . '|\bhold(?:s|ing)?\s+nothing\s+personal\b/i';

    /** @var string Pattern of a sentence disclaiming a claim: nothing, never, no or not, then a verb of claiming. */
    private const string DISCLAIMER = '/\b(?:nothing|never|no|not|nobody)\b(?:\s+[\w\']+){0,3}?\s+claim(?:s|ed)\b/i';

    /** @var string Pattern of a claim that destruction is stopped rather than made detectable. */
    private const string PREVENTION = '/(?<!neither\s)(?<!not\s)(?<!never\s)\bprevents?\b|\bcannot\s+be\s+(?:deleted|destroyed|restored)\b'
        . '|(?<!never\s)(?<!not\s)\bimpossible\b/i';

    /** @var string Pattern of what such a claim is about: an erasure, a hold, a trigger, a key, the journal, a marker or credentials. */
    private const string PREVENTION_SUBJECT = '/\b(?:eras\w*|hold\w*|trigger\w*|keys?|journal\w*|markers?|credentials?|wrap\w*)\b/i';

    /**
     * The privacy note has exactly the standard sections around its own.
     *
     * @return void
     */
    public function testThePrivacyNoteHasItsSectionsInOrder(): void
    {
        $note = self::withoutCodeBlocks(self::read(self::PRIVACY_NOTE));

        preg_match_all('/^## (.+)$/m', $note, $sections);

        self::assertStringStartsWith("# Privacy\n", $note);
        self::assertSame(self::SECTIONS, $sections[1]);
    }

    /**
     * Rows of `[section, statement]`: what the privacy note states, and where.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function providePrivacyStatements(): iterable
    {
        yield from [
            'two-guarantees'       => ['Purpose', self::GUARANTEES],
            'revoked-and-complete' => ['Erasure', 'Revoked in the live store is what the package does; erasure complete is the operator\'s procedure across the estate'],
            'domain-separation'    => ['Keys', 'The derivation gives domain separation, not independence from `app.key`'],
            'recall'               => ['Reading', 'A decryption already returned cannot be recalled.'],
            'not-erased'           => ['Invariants', 'Erasure destroys keys; it erases no reference, no retained value and no row.'],
            'units'                => ['Invariants', self::UNITS],
            'article-17'           => ['Invariants', 'a hold is not a blanket Article 17 exemption for every fragment of a person'],
            'sqlite-session'       => ['Keys', 'on SQLite a key created inside a host transaction rolls back with it'],
            'relocation'           => ['Encryption', 'An envelope copied to another entry, path or log reads `unreadable`'],
            'reveal-scope'         => ['Reading', self::REVEAL_SCOPE],
        ];
    }

    /**
     * The privacy note makes each statement in its section, however wrapped.
     *
     * @param  string  $section
     * @param  string  $statement
     * @return void
     */
    #[DataProvider('providePrivacyStatements')]
    public function testEachPrivacyStatementIsMade(string $section, string $statement): void
    {
        self::assertStringContainsString($statement, self::collapsed(self::section(self::read(self::PRIVACY_NOTE), $section)));
    }

    /**
     * Rows of `[value, section]`: every erasure refusal and status, by section.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideErasureValues(): iterable
    {
        foreach (ErasureRefusal::cases() as $refusal) {
            yield 'refusal ' . $refusal->value => [$refusal->value, 'Failure / Edge Cases'];
        }

        foreach (ErasureStatus::cases() as $status) {
            yield 'status ' . $status->value => [$status->value, 'Erasure'];
        }
    }

    /**
     * Every erasure refusal and status is named, in code type, in its section.
     *
     * @param  string  $value
     * @param  string  $section
     * @return void
     */
    #[DataProvider('provideErasureValues')]
    public function testEachErasureValueIsNamedInItsSection(string $value, string $section): void
    {
        $text = self::section(self::read(self::PRIVACY_NOTE), $section);

        self::assertStringContainsString('`' . $value . '`', $text, sprintf('The %s section does not name `%s`.', $section, $value));
    }

    /**
     * Every table setting is in the note's inventory of stores.
     *
     * @return void
     */
    public function testTheInventoryNamesEveryTableSetting(): void
    {
        $config = require self::root() . '/config/audit-log.php';

        self::assertIsArray($config);

        $tables  = array_values(array_filter(self::leafKeys($config), static fn (string $key): bool => preg_match('/(?:\A|[._])table\z/', $key) === 1));
        $section = self::section(self::read(self::PRIVACY_NOTE), self::INVENTORY);

        self::assertNotSame([], $tables);

        foreach ($tables as $table) {
            self::assertStringContainsString('`' . $table . '`', $section, sprintf('The inventory of stores does not name `%s`.', $table));
        }
    }

    /**
     * No document claims a store, a record or a value holds no personal data.
     *
     * @return void
     */
    public function testNoDocumentClaimsAStoreHoldsNoPersonalData(): void
    {
        self::assertContains(self::PRIVACY_NOTE, self::documents());
        self::assertContains('/README.md', self::documents());

        foreach (self::documents() as $path) {
            self::assertSame([], self::personalDataClaimsIn(self::read($path)), sprintf('%s claims something holds no personal data.', $path));
        }
    }

    /**
     * The claim pattern finds each form, across lines, and spares a disclaimer.
     *
     * @return void
     */
    public function testTheClaimPatternFindsEachFormAndSparesADisclaimer(): void
    {
        $claims = [
            'The receipt holds no personal data.',
            "Each row contains no personal\n  data.",
            'A fingerprint is not personal data.',
            'No personal data is stored in the journal.',
            'The list is free of personal data.',
            'The row is free of secrets or of personal data.',
            'They carry no personal data.',
            'The marker holds nothing personal.',
        ];

        foreach ($claims as $claim) {
            self::assertSame([self::collapsed($claim)], self::personalDataClaimsIn($claim), $claim);
        }

        $spared = [
            'A note is free text, and nothing claims it holds no personal data or secrets.',
            'A note is free text, and is never claimed free of secrets or of personal data.',
            "No store is claimed\n  to hold no personal data.",
            'A fingerprint is personal data while linkable.',
            'The spill and the outbox hold personal data.',
            'A receipt holds no value of the record.',
        ];

        foreach ($spared as $text) {
            self::assertSame([], self::personalDataClaimsIn($text), $text);
        }

        self::assertSame(['The receipt holds no personal data.'], self::personalDataClaimsIn("Nothing claims a note is safe.\n\nThe receipt holds no personal data."));
    }

    /**
     * The prevention pattern finds each form and spares a negation.
     *
     * @return void
     */
    public function testThePreventionPatternFindsEachForm(): void
    {
        $claims = [
            'Erasure prevents a restore.',
            'A hold prevents the erasure of a key.',
            'The trigger prevents a key from being deleted.',
            'An erased key cannot be restored.',
            "A destroyed key cannot\n  be destroyed again.",
            'A key use cannot be deleted.',
            'Restoring an erased key is impossible.',
            'Deleting the journal is Impossible.',
        ];

        foreach ($claims as $claim) {
            self::assertSame([self::collapsed($claim)], self::preventionClaimsIn($claim), $claim);
        }

        $spared = [
            'An erasure makes a restore detectable, never impossible.',
            'The journal makes it detectable, not impossible.',
            'Verification detects a change to a key and neither prevents nor repairs one.',
            'A hold does not prevent a key from being destroyed.',
            'A trigger cannot prevent the owner dropping it.',
            'An erased field cannot be read.',
            'A cache prevents a second query.',
        ];

        foreach ($spared as $text) {
            self::assertSame([], self::preventionClaimsIn($text), $text);
        }
    }

    /**
     * No document claims an erasure, hold, trigger or the journal stops what
     * credentials can do.
     *
     * @return void
     */
    public function testNoDocumentClaimsErasurePreventsWhatCredentialsCanDo(): void
    {
        self::assertContains('/docs/design/threat-model.md', self::documents());

        foreach (self::documents() as $path) {
            self::assertSame([], self::preventionClaimsIn(self::read($path)), sprintf('%s claims destruction is prevented.', $path));
        }
    }

    /**
     * Sentences claiming something holds no personal data, disclaimers aside.
     *
     * @param  string  $markdown
     * @return list<string>
     */
    private static function personalDataClaimsIn(string $markdown): array
    {
        return array_values(array_filter(
            self::sentences($markdown),
            static fn (string $sentence): bool => preg_match(self::NO_PERSONAL_DATA, $sentence) === 1 && preg_match(self::DISCLAIMER, $sentence) !== 1,
        ));
    }

    /**
     * The sentences claiming something stops destruction, whitespace collapsed.
     *
     * @param  string  $markdown
     * @return list<string>
     */
    private static function preventionClaimsIn(string $markdown): array
    {
        return array_values(array_filter(
            self::sentences($markdown),
            static fn (string $sentence): bool => preg_match(self::PREVENTION, $sentence) === 1 && preg_match(self::PREVENTION_SUBJECT, $sentence) === 1,
        ));
    }

    /**
     * Sentences outside code blocks, split at sentence ends and blank lines.
     *
     * @param  string  $markdown
     * @return list<string>
     */
    private static function sentences(string $markdown): array
    {
        $sentences = [];

        foreach (preg_split('/\n\s*\n/', self::withoutCodeBlocks($markdown)) ?: [] as $paragraph) {
            foreach (preg_split('/(?<=[.!?])\s+/', trim(self::collapsed($paragraph))) ?: [] as $sentence) {

                if ($sentence === '') {
                    continue;
                }

                $sentences[] = $sentence;
            }
        }

        return $sentences;
    }

    /**
     * The README and every Markdown file under docs, by path from the root.
     *
     * @return list<string>
     */
    private static function documents(): array
    {
        $root  = self::root();
        $files = ['/README.md'];

        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/docs', \FilesystemIterator::SKIP_DOTS));

        foreach ($iterator as $file) {

            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'md') {
                continue;
            }

            $files[] = substr($file->getPathname(), strlen($root));
        }

        sort($files);

        return $files;
    }

    /**
     * The configuration's leaf paths, lists and empty arrays included.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $config
     * @param  string  $prefix
     * @return list<string>
     */
    private static function leafKeys(array $config, string $prefix = ''): array
    {
        $keys = [];

        foreach ($config as $key => $value) {

            $path = $prefix . $key;

            if (is_array($value) && $value !== [] && !array_is_list($value)) {
                $keys = [...$keys, ...self::leafKeys($value, $path . '.')];

                continue;
            }

            $keys[] = $path;
        }

        return $keys;
    }
}
