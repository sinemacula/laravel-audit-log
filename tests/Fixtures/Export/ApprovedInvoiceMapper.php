<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Export;

use SineMacula\Laravel\AuditLog\Contracts\OcsfMapper;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * Classifies an approved invoice as OCSF API Activity (class 6003, in
 * Application Activity), activity 3, Update: the actor as a user, the code as
 * the API operation, and the client's address as the source endpoint, or the
 * source the record was captured on when the record holds no address.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApprovedInvoiceMapper implements OcsfMapper
{
    /**
     * The record as API Activity.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return array<string, array<array-key, mixed>|bool|int|string|null>
     */
    #[\Override]
    public function map(#[\SensitiveParameter] FinalisedRecord $record): array
    {
        $captured = $record->record;
        $address  = filter_var($captured->ip, FILTER_VALIDATE_IP) === false ? null : $captured->ip;

        return [
            'class_uid'     => 6003,
            'class_name'    => 'API Activity',
            'category_uid'  => 6,
            'category_name' => 'Application Activity',
            'activity_id'   => 3,
            'activity_name' => 'Update',
            'actor'         => ['user' => ['uid' => $captured->actorType . ':' . $captured->actorId]],
            'api'           => ['operation' => $captured->event],
            'src_endpoint'  => $address === null ? ['uid' => $captured->sourceId] : ['ip' => $address],
        ];
    }
}
