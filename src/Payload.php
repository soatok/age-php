<?php
declare(strict_types=1);
namespace Soatok\Age;

use Random\RandomException;
use SensitiveParameter;
use Soatok\Age\Exception\DecryptException;
use SodiumException;

final class Payload
{
    public const CHUNK_SIZE = 65536; // 64 KiB
    private const TAG_SIZE = 16;    // Poly1305 tag
    private const NONCE_SIZE = 16;  // Payload nonce (HKDF salt)
    public const ENC_CHUNK_SIZE = self::CHUNK_SIZE + self::TAG_SIZE;

    /**
     * @throws RandomException
     */
    public static function encrypt(
        #[SensitiveParameter]
        string $fileKey,
        #[SensitiveParameter]
        string $plaintext
    ): string {
        $nonce = random_bytes(self::NONCE_SIZE);
        $streamKey = hash_hkdf('sha256', $fileKey, 32, 'payload', $nonce);

        $output = $nonce;
        $offset = 0;
        $total = strlen($plaintext);

        if ($total === 0) {
            $output .= self::encryptChunk($streamKey, '', 0, true);
            return $output;
        }

        while ($offset < $total) {
            $chunk = substr($plaintext, $offset, self::CHUNK_SIZE);
            $remaining = $total - $offset;
            $isLast = $remaining <= self::CHUNK_SIZE;
            $counter = intdiv($offset, self::CHUNK_SIZE);

            $output .= self::encryptChunk($streamKey, $chunk, $counter, $isLast);
            $offset += self::CHUNK_SIZE;
        }

        return $output;
    }

    /**
     * @throws DecryptException
     */
    public static function decrypt(
        #[SensitiveParameter]
        string $fileKey,
        string $payload
    ): string {
        if (strlen($payload) < self::NONCE_SIZE) {
            throw new DecryptException('Payload too short for nonce');
        }

        $nonce = substr($payload, 0, self::NONCE_SIZE);
        $streamKey = hash_hkdf('sha256', $fileKey, 32, 'payload', $nonce);
        $data = substr($payload, self::NONCE_SIZE);

        return self::decryptStream($streamKey, $data);
    }

    /**
     * @throws DecryptException
     */
    private static function decryptStream(
        string $streamKey,
        string $data
    ): string {
        $dataLen = strlen($data);
        if ($dataLen === 0) {
            throw new DecryptException('Empty payload (no chunks)');
        }

        $plaintext = '';
        $offset = 0;
        $counter = 0;
        $sawFinal = false;

        while ($offset < $dataLen) {
            if ($sawFinal) {
                throw new DecryptException('Trailing data after final chunk');
            }

            $remaining = $dataLen - $offset;
            $chunkLen = min($remaining, self::ENC_CHUNK_SIZE);
            $chunk = substr($data, $offset, $chunkLen);
            $offset += $chunkLen;
            $atEnd = ($offset >= $dataLen);

            [$decrypted, $isFinal] = self::decryptChunk($streamKey, $chunk, $counter, $atEnd);

            $sawFinal = $isFinal;

            // Non-first empty chunk is invalid
            if ($decrypted === '' && $counter > 0) {
                throw new DecryptException('Empty non-first chunk');
            }

            $plaintext .= $decrypted;
            $counter++;
        }

        if (!$sawFinal) {
            throw new DecryptException('Payload ended without a final chunk');
        }

        return $plaintext;
    }

    private static function encryptChunk(
        #[SensitiveParameter]
        string $key,
        #[SensitiveParameter]
        string $plaintext,
        int $counter,
        bool $last
    ): string {
        $nonce = self::makeNonce($counter, $last);
        return sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
            $plaintext,
            '',
            $nonce,
            $key
        );
    }

    /**
     * @return array{string, bool}
     *
     * @throws DecryptException
     * @throws SodiumException
     */
    private static function decryptChunk(
        #[SensitiveParameter]
        string $key,
        string $chunk,
        int $counter,
        bool $atEnd
    ): array {
        if (strlen($chunk) < self::TAG_SIZE) {
            throw new DecryptException('Chunk too short');
        }
        if ($atEnd || strlen($chunk) < self::ENC_CHUNK_SIZE) {
            return [self::tryDecrypt($key, $chunk, $counter, true), true];
        }
        $result = self::tryDecryptOrFalse($key, $chunk, $counter, false);
        if ($result !== false) {
            return [$result, false];
        }
        return [self::tryDecrypt($key, $chunk, $counter, true), true];
    }

    /**
     * @throws DecryptException
     * @throws SodiumException
     */
    private static function tryDecrypt(
        #[SensitiveParameter]
        string $key,
        string $chunk,
        int $counter,
        bool $last
    ): string {
        $nonce = self::makeNonce($counter, $last);
        $result = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
            $chunk,
            '',
            $nonce,
            $key
        );
        if (!is_string($result)) {
            throw new DecryptException('Failed to decrypt payload chunk');
        }
        return $result;
    }

    /**
     * @throws SodiumException
     */
    private static function tryDecryptOrFalse(
        #[SensitiveParameter]
        string $key,
        string $chunk,
        int $counter,
        bool $last
    ): string|false {
        $nonce = self::makeNonce($counter, $last);
        return sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
            $chunk,
            '',
            $nonce,
            $key
        );
    }

    /**
     * Bytes 0-10: big-endian chunk counter (88 bits)
     * Byte 11: 0x01 if final chunk, 0x00 otherwise
     */
    private static function makeNonce(int $counter, bool $last): string
    {
        // 3 zero bytes + 8-byte big-endian counter + 1-byte flag
        return "\x00\x00\x00" . pack('J', $counter)
            . pack('C', (int)($last));
    }
}
