<?php
declare(strict_types=1);
namespace Soatok\Age;

interface IdentityInterface
{
    /**
     * Attempt to unwrap a file key from the given stanza
     *
     * Returns the 16-byte file key if this stanza is addressed to this identity, or null if the stanza is not
     * recognized (wrong type or different recipient)
     */
    public function unwrap(Stanza $stanza): ?string;
}
