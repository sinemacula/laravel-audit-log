<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\RewrapCommitments;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\TestCase;

/**
 * Feature tests for what the journal's rewrap rows commit each key to: a key
 * no rewrap lists must be live; a listed key must hold the state, wrapping key
 * and wrapped key its latest listing left; a later listing replaces an
 * earlier one; and rows of other kinds, and listings that are not well formed,
 * commit nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RewrapCommitments::class)]
final class RewrapCommitmentsTest extends TestCase
{
    use MakesSubjectKeys;

    /** @var string The data key of every key: thirty-two bytes. */
    private const string DATA_KEY = 'a data key of thirty-two bytes!!';

    /**
     * Bind the package's key wrapper.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->keyWrapper();
    }

    /**
     * A key no rewrap lists is clean while live and substituted once
     * superseded; an erased key gives no finding here.
     *
     * @return void
     */
    public function testAnUnlistedKeyMustBeLive(): void
    {
        $commitments = new RewrapCommitments;
        $key         = $this->key();

        self::assertNull($commitments->findingOf($key));
        self::assertSame(Finding::KEY_SUBSTITUTED, $commitments->findingOf(self::inState($key, KeyState::SUPERSEDED)));
        self::assertNull($commitments->findingOf(self::inState($key, KeyState::ERASED)));
    }

    /**
     * A listed key must be as its latest listing left it, whose later listing
     * replaces the earlier: its state, its wrapping key id and its wrapped key
     * each compared.
     *
     * @return void
     */
    public function testAListedKeyMustBeAsItsLatestListingLeftIt(): void
    {
        $commitments = new RewrapCommitments;
        $key         = $this->key();

        $commitments->fold($this->rewrapRow($key, 'live', 'old', 'digest-old'));
        $commitments->fold($this->rewrapRow($key, KeyState::SUPERSEDED->value, (string) $key->wrapKeyId, (string) $key->wrappedDigest()));

        self::assertNull($commitments->findingOf(self::inState($key, KeyState::SUPERSEDED)));
        self::assertSame(Finding::KEY_SUBSTITUTED, $commitments->findingOf($key));
        self::assertSame(Finding::KEY_SUBSTITUTED, $commitments->findingOf(self::inState($key, KeyState::SUPERSEDED, ['wrap_key_id' => 'other'])));
        self::assertSame(Finding::KEY_SUBSTITUTED, $commitments->findingOf(self::inState($key, KeyState::SUPERSEDED, ['wrapped_key' => 'another-wrapped-key'])));
    }

    /**
     * A row of another kind, and a listing missing any of its values, commit
     * nothing, so the key is judged as unlisted.
     *
     * @return void
     */
    public function testOtherRowsAndMalformedListingsCommitNothing(): void
    {
        $commitments = new RewrapCommitments;
        $key         = $this->key();
        $superseded  = self::inState($key, KeyState::SUPERSEDED);

        $commitments->fold($this->journalRow(JournalKind::REINSTATE, ['keys' => [['key_id' => $key->id, 'after' => ['state' => 'superseded']]]]));
        $commitments->fold($this->journalRow(JournalKind::REWRAP, ['run_id' => 'r', 'rotate' => true, 'keys' => [
            ['key_id' => $key->id, 'after' => ['state' => 'superseded', 'wrap_key_id' => (string) $key->wrapKeyId]],
            ['key_id' => $key->id],
            'not a listing',
        ], 'skipped' => []]));

        self::assertSame(Finding::KEY_SUBSTITUTED, $commitments->findingOf($superseded));
    }

    /**
     * A signed live key of a unit of its own, as a row the store would read.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     */
    private function key(): SubjectKeyRow
    {
        return $this->signedSubjectKey(new KeyUnit(Reference::of('App\Models\User', '42'), null, self::KEY_CATEGORY), 1, self::DATA_KEY);
    }

    /**
     * A believed rewrap row listing the key with the state, wrapping key id and
     * wrapped digest given after it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @param  string  $state
     * @param  string  $wrapKeyId
     * @param  string  $digest
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private function rewrapRow(SubjectKeyRow $key, string $state, string $wrapKeyId, string $digest): JournalRow
    {
        $after = ['state' => $state, 'wrapped_digest' => $digest, 'wrap_key_id' => $wrapKeyId];

        $listed = [['key_id' => $key->id, 'before' => $after, 'after' => $after]];

        return $this->journalRow(JournalKind::REWRAP, ['run_id' => 'r', 'rotate' => true, 'keys' => $listed, 'skipped' => []]);
    }

    /**
     * The key as it would be read in the state given, with any other columns
     * changed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState  $state
     * @param  array<string, string>  $columns
     * @return \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     */
    private static function inState(SubjectKeyRow $key, KeyState $state, array $columns = []): SubjectKeyRow
    {
        $row = [...$key->toRow(), 'state' => $state->value, ...$columns];

        if (!$state->holdsAKey()) {
            $row = [...$row, 'wrapped_key' => null, 'wrap_key_id' => null, 'erasure_id' => '01932b4e-9000-7000-8000-0000000000e1'];
        }

        return SubjectKeyRow::fromRow($row);
    }
}
