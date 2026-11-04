<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Querying\Procedure;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The reading guide's subject access policy, `App\Audit\SubjectAccessPolicy`,
 * whose text from its class declaration to its end is the guide's own: the
 * investigator reads, counts and exports the subject's activity, as the actor
 * or the subject of an entry, or every entry while finding the subject's
 * fragments, with the encrypted fields revealed, and verifies an export in the
 * audit category; anyone else sees nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubjectAccessPolicy implements AuditAccessPolicy
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $investigator
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  bool  $fragments
     */
    public function __construct(

        /** The person answering the request, as the application authenticated them. */
        #[\SensitiveParameter]
        private Authenticatable $investigator,

        /** The person the request is about. */
        private Reference $subject,

        /** Whether the investigator is finding the entries that hold the subject's fragments. */
        private bool $fragments = false,
    ) {}

    /**
     * For the investigator, the audit category, where an export is journalled,
     * to verify an export; otherwise, with the encrypted fields revealed, the
     * subject's activity, as the actor or the subject of an entry, or every
     * entry while finding the subject's fragments, which can be in an entry
     * about anyone. Nothing for anyone else.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     */
    #[\Override]
    public function scope(#[\SensitiveParameter] Authenticatable|Reference $viewer, ReadPurpose $purpose): AccessScope
    {
        if ($viewer !== $this->investigator) {
            return AccessScope::none();
        }

        if ($purpose === ReadPurpose::VERIFY) {
            return AccessScope::all()->onlyCategories('audit');
        }

        $scope = $this->fragments ? AccessScope::all() : AccessScope::all()->onlyAbout($this->subject);

        return $scope->revealingEncryptedFields();
    }
}
