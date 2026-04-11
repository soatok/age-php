<?php
declare(strict_types=1);
namespace Soatok\Age;

use SensitiveParameter;
use Soatok\Age\Exception\DecryptException;
use Soatok\Age\Exception\InternalException;
use SodiumException;

final class Primitives
{
    /**
     * @throws SodiumException
     */
    public static function aeadEncrypt(
        #[SensitiveParameter]
        string $key,
        #[SensitiveParameter]
        string $plaintext
    ): string {
        $nonce = str_repeat("\0", SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
        return sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
            $plaintext,
            '',
            $nonce,
            $key
        );
    }

    /**
     * @throws DecryptException
     * @throws InternalException
     * @throws SodiumException
     */
    public static function aeadDecrypt(
        #[SensitiveParameter]
        string $key,
        int $expectedSize,
        string $ciphertext
    ): string {
        $tagSize = SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;
        if (strlen($ciphertext) !== $expectedSize + $tagSize) {
            throw new InternalException('Ciphertext length does not match expected size');
        }
        $nonce = str_repeat("\0", SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
        $result = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
            $ciphertext,
            '',
            $nonce,
            $key
        );
        if (!is_string($result)) {
            throw new InternalException('AEAD decryption failed');
        }
        return $result;
    }
}
