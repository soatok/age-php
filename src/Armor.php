<?php
declare(strict_types=1);
namespace Soatok\Age;

use ParagonIE\ConstantTime\Base64;
use Soatok\Age\Exception\ParseException;
use Throwable;

final class Armor
{
    private const HEADER = '-----BEGIN AGE ENCRYPTED FILE-----';
    private const FOOTER = '-----END AGE ENCRYPTED FILE-----';
    private const COLUMNS = 64;

    public static function encode(string $data): string
    {
        $b64 = base64_encode($data);
        $wrapped = rtrim(chunk_split($b64, self::COLUMNS, "\n"), "\n");
        return self::HEADER . "\n" . $wrapped . "\n" . self::FOOTER . "\n";
    }

    /**
     * @throws ParseException
     */
    public static function decode(string $armored): string
    {
        // Normalize line endings
        $armored = str_replace("\r\n", "\n", $armored);

        // Strip leading/trailing whitespace
        $armored = trim($armored);

        // Find header
        $headerPos = strpos($armored, self::HEADER);
        if ($headerPos === false) {
            throw new ParseException('Missing armor header');
        }

        // Check nothing but whitespace before header
        $before = substr($armored, 0, $headerPos);
        if (trim($before) !== '') {
            throw new ParseException('Garbage before armor header');
        }

        $afterHeader = $headerPos + strlen(self::HEADER);
        if (!isset($armored[$afterHeader]) || $armored[$afterHeader] !== "\n") {
            throw new ParseException('Expected newline after armor header');
        }
        $bodyStart = $afterHeader + 1;

        // Find footer
        $footerPos = strpos($armored, self::FOOTER, $bodyStart);
        if ($footerPos === false) {
            throw new ParseException('Missing armor footer');
        }

        // Check nothing but whitespace after footer
        $afterFooter = $footerPos + strlen(self::FOOTER);
        $after = substr($armored, $afterFooter);
        if (trim($after) !== '') {
            throw new ParseException('Garbage after armor footer');
        }
        $body = substr($armored, $bodyStart, $footerPos - $bodyStart);
        return self::decodeBody($body);
    }

    /**
     * @throws ParseException
     */
    private static function decodeBody(string $body): string
    {
        // Empty body is valid (decodes to empty bytes)
        if ($body === '' || $body === "\n") {
            return '';
        }
        // Body must end with exactly one newline before the footer
        if (!str_ends_with($body, "\n")) {
            throw new ParseException('Armor body must end with newline');
        }
        // Remove trailing newline, then split
        $body = substr($body, 0, -1);
        $lines = explode("\n", $body);
        $lineCount = count($lines);

        $b64 = '';
        foreach ($lines as $i => $line) {
            $isLast = ($i === $lineCount - 1);
            $len = strlen($line);

            if ($len > self::COLUMNS) {
                throw new ParseException("Armor line " . ($i + 1) . " exceeds 64 characters");
            }
            if ($isLast && $len === 0) {
                throw new ParseException('Empty trailing line in armor body is non-canonical');
            }

            // All lines except the last must be exactly 64 chars
            if (!$isLast && $len !== self::COLUMNS) {
                throw new ParseException("Armor line " . ($i + 1) . " is $len chars, expected 64");
            }

            // Validate characters (standard base64 with padding)
            if ($len > 0 && preg_match('/[^A-Za-z0-9+\/=]/', $line)) {
                throw new ParseException("Invalid character in armor line " . ($i + 1));
            }

            // Padding characters may only appear at the end of the last line
            if (!$isLast && str_contains($line, '=')) {
                throw new ParseException("Padding in non-final armor line " . ($i + 1));
            }
            $b64 .= $line;
        }
        try {
            $decoded = Base64::decode($b64, true);
        } catch (Throwable $e) {
            throw new ParseException('Could not decode base64', 0, $e);
        }
        if (Base64::encode($decoded) !== $b64) {
            throw new ParseException('Non-canonical base64 in armor');
        }
        return $decoded;
    }
}
