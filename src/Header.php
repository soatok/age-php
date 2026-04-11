<?php
declare(strict_types=1);
namespace Soatok\Age;

use ParagonIE\ConstantTime\Base64;
use Soatok\Age\Exception\{
    DecryptException,
    ParseException
};
use Throwable;

final class Header
{
    private const VERSION_LINE = "age-encryption.org/v1\n";
    private const FOOTER_PREFIX = '---';
    private const STANZA_PREFIX = '->';
    private const BYTES_PER_LINE = 48;

    /**
     * @param Stanza[] $stanzas
     * @param string $mac
     */
    public function __construct(
        public readonly array $stanzas,
        public readonly string $mac,
    ) {}

    public function serialize(): string
    {
        return $this->serializeWithoutMac() . ' ' . Base64::encodeUnpadded($this->mac) . "\n";
    }

    /**
     * @return string
     */
    public function serializeWithoutMac(): string
    {
        $out = self::VERSION_LINE;
        foreach ($this->stanzas as $stanza) {
            $out .= $stanza->serialize();
        }
        $out .= self::FOOTER_PREFIX;
        return $out;
    }

    /**
     * Compute the header MAC for a given file key.
     */
    public static function computeMac(string $fileKey, string $headerWithoutMac): string
    {
        $hmacKey = hash_hkdf('sha256', $fileKey, 32, 'header');
        return hash_hmac('sha256', $headerWithoutMac, $hmacKey, true);
    }

    /**
     * Create a header with computed MAC.
     *
     * @param Stanza[] $stanzas
     */
    public static function create(array $stanzas, string $fileKey): self
    {
        $header = new self($stanzas, '');
        $headerBytes = $header->serializeWithoutMac();
        $mac = self::computeMac($fileKey, $headerBytes);
        return new self($stanzas, $mac);
    }

    /**
     * @throws DecryptException
     */
    public function verifyMac(string $fileKey): void
    {
        $expected = self::computeMac($fileKey, $this->serializeWithoutMac());
        if (!hash_equals($expected, $this->mac)) {
            throw new DecryptException('Header MAC verification failed');
        }
    }

    /**
     * Parse an age v1 header from binary data
     *
     * @return array{header: self, offset: int}
     * @throws ParseException
     */
    public static function parse(string $data): array
    {
        $pos = 0;
        $len = strlen($data);

        // Version line
        $nlPos = strpos($data, "\n", $pos);
        if ($nlPos === false) {
            throw new ParseException('Missing version line');
        }
        $versionLine = substr($data, $pos, $nlPos - $pos + 1);
        if ($versionLine !== self::VERSION_LINE) {
            throw new ParseException(
                "Unexpected version line: " . rtrim($versionLine, "\n")
            );
        }
        $pos = $nlPos + 1;

        // Parse stanzas and footer
        $stanzas = [];
        while ($pos < $len) {
            $prefix = substr($data, $pos, 3);

            if (hash_equals($prefix, self::FOOTER_PREFIX)) {
                break;
            }

            $mismatchPrefix = !hash_equals($prefix, self::STANZA_PREFIX . ' ');
            $mismatchTwoBytes = !hash_equals(substr($prefix, 0, 2), self::STANZA_PREFIX);
            if ($mismatchPrefix && $mismatchTwoBytes) {
                throw new ParseException("Expected stanza or footer at offset $pos");
            }

            $result = self::parseStanza($data, $pos);
            $stanzas[] = $result['stanza'];
            $pos = $result['offset'];
        }

        if (empty($stanzas)) {
            throw new ParseException('No recipient stanzas found');
        }

        // Parse footer: "--- <base64mac>\n"
        $result = self::parseFooter($data, $pos);
        return [
            'header' => new self($stanzas, $result['mac']),
            'offset' => $result['offset'],
        ];
    }

    /**
     * @return array{stanza: Stanza, offset: int}
     */
    private static function parseStanza(string $data, int $pos): array
    {
        // Arg line: "-> type arg1 arg2...\n"
        $nlPos = strpos($data, "\n", $pos);
        if ($nlPos === false) {
            throw new ParseException('Unterminated stanza arg line');
        }
        $argLine = substr($data, $pos, $nlPos - $pos);
        $pos = $nlPos + 1;

        if (!str_starts_with($argLine, '-> ')) {
            throw new ParseException("Malformed stanza: $argLine");
        }

        $parts = explode(' ', substr($argLine, 3));
        $parts = array_filter($parts, fn (string $s) => $s !== '');
        $parts = array_values($parts);
        if (count($parts) < 1) {
            throw new ParseException("Stanza has no type: $argLine");
        }

        foreach ($parts as $part) {
            if (!self::isValidArgument($part)) {
                throw new ParseException("Invalid stanza argument: $part");
            }
        }

        $type = $parts[0];
        $args = array_slice($parts, 1);

        // Body lines: 64-char full lines, then one short line
        $body = '';
        while (true) {
            $nlPos = strpos($data, "\n", $pos);
            if ($nlPos === false) {
                throw new ParseException('Unterminated stanza body');
            }
            $line = substr($data, $pos, $nlPos - $pos);
            $pos = $nlPos + 1;

            try {
                $decoded = Base64::decodeNoPadding($line);
            } catch (Throwable) {
                throw new ParseException('Invalid base64 encoding');
            }
            if (strlen($decoded) > self::BYTES_PER_LINE) {
                throw new ParseException("Stanza body line too long");
            }
            $body .= $decoded;
            if (strlen($decoded) < self::BYTES_PER_LINE) {
                break;
            }
        }

        return [
            'stanza' => new Stanza($type, $args, $body),
            'offset' => $pos,
        ];
    }

    /**
     * @return array{mac: string, offset: int}
     */
    private static function parseFooter(string $data, int $pos): array
    {
        $nlPos = strpos($data, "\n", $pos);
        if ($nlPos === false) {
            throw new ParseException('Unterminated footer line');
        }
        $line = substr($data, $pos, $nlPos - $pos);
        $pos = $nlPos + 1;

        $parts = explode(' ', $line);
        if (count($parts) !== 2 || $parts[0] !== self::FOOTER_PREFIX) {
            throw new ParseException("Malformed footer: $line");
        }

        try {
            $mac = Base64::decodeNoPadding($parts[1]);
        } catch (Throwable) {
            throw new ParseException('Invalid base64 encoding');
        }
        if (strlen($mac) !== 32) {
            throw new ParseException('Invalid MAC length');
        }

        return ['mac' => $mac, 'offset' => $pos];
    }

    /**
     * Check that a string contains only printable ASCII (0x21-0x7E)
     */
    private static function isValidArgument(string $s): bool
    {
        if ($s === '') {
            return false;
        }
        for ($i = 0, $len = strlen($s); $i < $len; $i++) {
            $c = Util::ord($s[$i]);
            if ($c < 33 || $c > 126) {
                return false;
            }
        }
        return true;
    }
}
