<?php
declare(strict_types=1);
namespace Soatok\Age;

abstract class Util
{
    /**
     * Convert an int to a byte without side-channels
     *
     * @param int $index
     * @return string
     */
    public static function chr(int $index): string
    {
        return pack('C', $index);
    }

    /**
     * Get byte index without side-channels
     *
     * @param string $character
     * @return int
     */
    public static function ord(string $character): int
    {
        $x = unpack('C', $character);
        return $x[1];
    }
}
