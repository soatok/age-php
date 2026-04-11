<?php
declare(strict_types=1);
namespace Soatok\Age\Hybrid\Mlkem768X25519;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\HPKE\AEAD\ChaCha20Poly1305;
use ParagonIE\HPKE\Hash;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\PostQuantumKEM;
use ParagonIE\HPKE\KEM\PQKEM\Algorithm;
use ParagonIE\HPKE\KEM\PQKEM\EncapsKey;
use Soatok\Age\Bech32;
use Soatok\Age\Exception\ParseException;
use Soatok\Age\RecipientInterface;
use Soatok\Age\Stanza;

final class HybridRecipient implements RecipientInterface
{
    private const HRP = 'age1pq';
    private const INFO = 'age-encryption.org/mlkem768x25519';
    private const ENC_KEY_SIZE = 1216;
    public const ALG = 'mlkem768x25519';

    public function __construct(
        private readonly string $publicKey,
    ) {
        if (strlen($publicKey) !== self::ENC_KEY_SIZE) {
            throw new InvalidArgumentException('X-Wing public key must be 1216 bytes');
        }
    }

    public static function fromString(string $s): self
    {
        $decoded = Bech32::decode(strtolower($s));
        if ($decoded['hrp'] !== self::HRP) {
            throw new ParseException("Invalid hybrid recipient HRP: {$decoded['hrp']}");
        }
        if (strlen($decoded['data']) !== self::ENC_KEY_SIZE) {
            throw new ParseException('Invalid hybrid recipient key length');
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
     * @param string $fileKey
     * @return Stanza[]
     * @throws HPKEException
     */
    public function wrap(string $fileKey): array
    {
        $hpke = self::buildHpke();
        $ek = new EncapsKey(Algorithm::XWing, $this->publicKey);

        [$enc, $ctx] = $hpke->setupBaseSender($ek, self::INFO);
        $ciphertext = $ctx->seal($fileKey, '');

        return [
            new Stanza(self::ALG, [Base64::encodeUnpadded($enc)], $ciphertext),
        ];
    }

    private static function buildHpke(): HPKE
    {
        return new HPKE(
            new PostQuantumKEM(Algorithm::XWing),
            new HKDF(Hash::Sha256),
            new ChaCha20Poly1305()
        );
    }
}
