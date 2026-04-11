<?php
declare(strict_types=1);
namespace Soatok\Age;

interface RecipientInterface
{
    /**
     * @param string $fileKey
     * @return Stanza[]
     */
    public function wrap(string $fileKey): array;
}
