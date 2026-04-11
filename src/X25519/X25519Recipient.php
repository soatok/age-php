<?php
declare(strict_types=1);
namespace Soatok\Age\X25519;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64;
use Random\RandomException;
use Soatok\Age\Bech32;
use Soatok\Age\Exception\ParseException;
use Soatok\Age\Primitives;
use Soatok\Age\RecipientInterface;
use Soatok\Age\Stanza;
use SodiumException;

final class X25519Recipient implements RecipientInterface
{
    private const HRP = 'age';
    private const KEY_LABEL = 'age-encryption.org/v1/X25519';
    private const KEY_SIZE = 32;

    public function __construct(private readonly string $publicKey)
    {
        if (strlen($publicKey) !== self::KEY_SIZE) {
            throw new InvalidArgumentException('X25519 public key must be 32 bytes');
        }
    }


    /**
     * @throws ParseException
     */
    public static function fromString(string $s): self
    {
        $decoded = Bech32::decode(strtolower($s));
        if ($decoded['hrp'] !== self::HRP) {
            throw new ParseException("Invalid X25519 recipient HRP: {$decoded['hrp']}");
        }
        if (strlen($decoded['data']) !== self::KEY_SIZE) {
            throw new ParseException('Invalid X25519 recipient key length');
        }
        return new self($decoded['data']);
    }

    public function encode(): string
    {
        return Bech32::encode(self::HRP, $this->publicKey);
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * @return Stanza[]
     * @throws SodiumException
     * @throws RandomException
     */
    public function wrap(string $fileKey): array
    {
        $ephemeralSecret = random_bytes(self::KEY_SIZE);
        $ephemeralShare = sodium_crypto_scalarmult_base($ephemeralSecret);

        $sharedSecret = sodium_crypto_scalarmult(
            $ephemeralSecret,
            $this->publicKey
        );

        $salt = $ephemeralShare . $this->publicKey;
        $wrapKey = hash_hkdf('sha256', $sharedSecret, 32, self::KEY_LABEL, $salt);
        $body = Primitives::aeadEncrypt($wrapKey, $fileKey);

        try {
            sodium_memzero($ephemeralSecret);
            sodium_memzero($sharedSecret);
            sodium_memzero($wrapKey);
        } catch (SodiumException) {
            // Best-effort zeroing
        }

        return [
            new Stanza('X25519', [Base64::encodeUnpadded($ephemeralShare)], $body),
        ];
    }
}
