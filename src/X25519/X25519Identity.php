<?php
declare(strict_types=1);
namespace Soatok\Age\X25519;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64;
use Random\RandomException;
use SensitiveParameter;
use Soatok\Age\Bech32;
use Soatok\Age\Exception\DecryptException;
use Soatok\Age\Exception\InternalException;
use Soatok\Age\Exception\ParseException;
use Soatok\Age\IdentityInterface;
use Soatok\Age\Primitives;
use Soatok\Age\Stanza;
use SodiumException;
use Throwable;

/**
 * X25519 identity (secret key).
 */
final class X25519Identity implements IdentityInterface
{
    private const HRP = 'age-secret-key-';
    private const KEY_LABEL = 'age-encryption.org/v1/X25519';
    private const KEY_SIZE = 32;
    private const FILE_KEY_SIZE = 16;
    private const WRAPPED_KEY_SIZE = 32; // 16 plaintext + 16 tag
    private readonly string $publicKey;

    public function __construct(
        #[SensitiveParameter]
        private readonly string $secretKey
    ) {
        if (strlen($secretKey) !== self::KEY_SIZE) {
            throw new InvalidArgumentException('X25519 secret key must be 32 bytes');
        }
        $this->publicKey = sodium_crypto_scalarmult_base($secretKey);
    }

    /**
     * @throws RandomException
     */
    public static function generate(): self
    {
        return new self(random_bytes(self::KEY_SIZE));
    }

    public static function fromString(
        #[SensitiveParameter]
        string $s
    ): self {
        $decoded = Bech32::decode(strtolower($s));
        if ($decoded['hrp'] !== self::HRP) {
            throw new ParseException("Invalid X25519 identity HRP: {$decoded['hrp']}");
        }
        if (strlen($decoded['data']) !== self::KEY_SIZE) {
            throw new ParseException('Invalid X25519 identity key length');
        }
        return new self($decoded['data']);
    }

    public function encode(): string
    {
        return strtoupper(Bech32::encode(self::HRP, $this->secretKey));
    }

    public function getRecipient(): X25519Recipient
    {
        return new X25519Recipient($this->publicKey);
    }

    /**
     * @throws DecryptException
     * @throws SodiumException
     */
    public function unwrap(Stanza $stanza): ?string
    {
        if ($stanza->type !== 'X25519') {
            return null;
        }
        if (count($stanza->args) !== 1) {
            throw new DecryptException('X25519 stanza must have exactly one argument');
        }
        try {
            $ephemeralShare = Base64::decodeNoPadding($stanza->args[0]);
        } catch (Throwable) {
            throw new ParseException('Invalid base64 encoding');
        }
        if (strlen($ephemeralShare) !== self::KEY_SIZE) {
            throw new DecryptException('X25519 ephemeral share must be 32 bytes');
        }
        if (strlen($stanza->body) !== self::WRAPPED_KEY_SIZE) {
            throw new DecryptException('X25519 stanza body must be 32 bytes');
        }

        $sharedSecret = sodium_crypto_scalarmult($this->secretKey, $ephemeralShare);

        $salt = $ephemeralShare . $this->publicKey;
        $wrapKey = hash_hkdf('sha256', $sharedSecret, 32, self::KEY_LABEL, $salt);

        try {
            $fileKey = Primitives::aeadDecrypt(
                $wrapKey,
                self::FILE_KEY_SIZE,
                $stanza->body
            );
        } catch (SodiumException|InternalException) {
            return null;
        } finally {
            try {
                sodium_memzero($sharedSecret);
                sodium_memzero($wrapKey);
            } catch (SodiumException) {
                // Best-effort
            }
        }
        return $fileKey;
    }
}
