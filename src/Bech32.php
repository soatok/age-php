<?php
declare(strict_types=1);
namespace Soatok\Age;

use Soatok\Age\Exception\ParseException;

final class Bech32
{
    private const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

    private const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    /**
     * @param string $hrp
     * @param string $data
     * @return string
     */
    public static function encode(string $hrp, string $data): string
    {
        $values = self::convertBits(
            array_values(unpack('C*', $data)),
            8,
            5,
            true
        );
        $checksum = self::createChecksum($hrp, $values);
        $encoded = '';
        foreach (array_merge($values, $checksum) as $v) {
            $encoded .= self::CHARSET[$v];
        }
        return $hrp . '1' . $encoded;
    }

    /**
     * Decode a Bech32 string.
     *
     * @return array{hrp: string, data: string}
     * @throws ParseException
     */
    public static function decode(string $bech): array
    {
        $lower = strtolower($bech);
        $upper = strtoupper($bech);
        if ($bech !== $lower && $bech !== $upper) {
            throw new ParseException('Bech32: mixed case');
        }
        // Normalize to lowercase:
        $bech = $lower;

        $pos = strrpos($bech, '1');
        if ($pos === false || $pos < 1 || $pos + 7 > strlen($bech)) {
            throw new ParseException('Bech32: invalid separator position');
        }

        $hrp = substr($bech, 0, $pos);
        $dataPart = substr($bech, $pos + 1);

        /** @var int[] $values */
        $values = [];
        for ($i = 0, $len = strlen($dataPart); $i < $len; $i++) {
            $idx = strpos(self::CHARSET, $dataPart[$i]);
            if ($idx === false) {
                throw new ParseException('Bech32: invalid character');
            }
            $values[] = $idx;
        }

        if (!self::verifyChecksum($hrp, $values)) {
            throw new ParseException('Bech32: invalid checksum');
        }

        // Strip the 6-character checksum
        $payload = array_slice($values, 0, -6);
        $decoded = self::convertBits($payload, 5, 8, false);

        return [
            'hrp' => $hrp,
            'data' => pack('C*', ...$decoded),
        ];
    }

    /**
     * @param int[] $data
     * @return int[]
     */
    private static function convertBits(
        array $data,
        int $fromBits,
        int $toBits,
        bool $pad
    ): array {
        $acc = 0;
        $bits = 0;
        $maxv = (1 << $toBits) - 1;
        $result = [];

        foreach ($data as $value) {
            $acc = ($acc << $fromBits) | $value;
            $bits += $fromBits;
            while ($bits >= $toBits) {
                $bits -= $toBits;
                $result[] = ($acc >> $bits) & $maxv;
            }
        }

        if ($pad) {
            if ($bits > 0) {
                $result[] = ($acc << ($toBits - $bits)) & $maxv;
            }
        } elseif ($bits >= $fromBits) {
            throw new ParseException('Bech32: excess padding');
        } elseif ((($acc << ($toBits - $bits)) & $maxv) !== 0) {
            throw new ParseException('Bech32: non-zero padding');
        }

        return $result;
    }

    private static function polymod(array $values): int
    {
        $chk = 1;
        foreach ($values as $v) {
            $b = $chk >> 25;
            $chk = (($chk & 0x1ffffff) << 5) ^ $v;
            for ($i = 0; $i < 5; $i++) {
                $chk ^= (($b >> $i) & 1) ? self::GENERATOR[$i] : 0;
            }
        }
        return $chk;
    }

    /** @return int[] */
    private static function hrpExpand(string $hrp): array
    {
        $expand = [];
        for ($i = 0, $len = strlen($hrp); $i < $len; $i++) {
            $expand[] = Util::ord($hrp[$i]) >> 5;
        }
        $expand[] = 0;
        for ($i = 0, $len = strlen($hrp); $i < $len; $i++) {
            $expand[] = Util::ord($hrp[$i]) & 31;
        }
        return $expand;
    }

    /**
     * @param string $hrp
     * @param int[] $values
     * @return int[]
     */
    private static function createChecksum(string $hrp, array $values): array
    {
        $polymod = self::polymod(
            array_merge(self::hrpExpand($hrp), $values, [0, 0, 0, 0, 0, 0])
        ) ^ 1;
        $checksum = [];
        for ($i = 0; $i < 6; $i++) {
            $checksum[] = ($polymod >> (5 * (5 - $i))) & 31;
        }
        return $checksum;
    }

    private static function verifyChecksum(string $hrp, array $values): bool
    {
        return self::polymod(array_merge(self::hrpExpand($hrp), $values)) === 1;
    }
}
