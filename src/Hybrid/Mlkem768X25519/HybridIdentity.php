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
use ParagonIE\HPKE\KEM\PQKEM\DecapsKey;
use ParagonIE\PQCrypto\Exception\PQCryptoCompatException;
use ParagonIE\PQCrypto\Internal\Keccak;
use ParagonIE\PQCrypto\Internal\MLKem\Operations;
use Random\RandomException;
use SensitiveParameter;
use Soatok\Age\Bech32;
use Soatok\Age\Exception\DecryptException;
use Soatok\Age\Exception\ParseException;
use Soatok\Age\IdentityInterface;
use Soatok\Age\Stanza;
use SodiumException;
use Throwable;

final class HybridIdentity implements IdentityInterface
{
    private const HRP = 'age-secret-key-pq-';
    private const INFO = 'age-encryption.org/mlkem768x25519';
    private const SEED_SIZE = 32;
    private const ENC_SIZE = 1120;
    private const BODY_SIZE = 32;

    private readonly string $publicKey;

    /**
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    public function __construct(
        #[SensitiveParameter]
        private readonly string $seed,
    ) {
        if (strlen($seed) !== self::SEED_SIZE) {
            throw new InvalidArgumentException('X-Wing identity seed must be 32 bytes');
        }
        $this->publicKey = self::derivePublicKey($seed);
    }

    /**
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public static function generate(): self
    {
        return new self(random_bytes(self::SEED_SIZE));
    }

    /**
     * @throws ParseException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    public static function fromString(string $s): self
    {
        $decoded = Bech32::decode(strtolower($s));
        if ($decoded['hrp'] !== self::HRP) {
            throw new ParseException("Invalid hybrid identity HRP: {$decoded['hrp']}");
        }
        if (strlen($decoded['data']) !== self::SEED_SIZE) {
            throw new ParseException('Invalid hybrid identity key length');
        }
        return new self($decoded['data']);
    }

    public function encode(): string
    {
        return strtoupper(Bech32::encode(self::HRP, $this->seed));
    }

    public function getRecipient(): HybridRecipient
    {
        return new HybridRecipient($this->publicKey);
    }

    /**
     * @throws DecryptException
     * @throws HPKEException
     */
    public function unwrap(Stanza $stanza): ?string
    {
        if ($stanza->type !== 'mlkem768x25519') {
            return null;
        }
        if (count($stanza->args) !== 1) {
            throw new DecryptException('mlkem768x25519 stanza must have exactly one argument');
        }

        try {
            $enc = Base64::decode($stanza->args[0], true);
        } catch (Throwable $e) {
            throw new DecryptException('invalid base64', 0, $e);
        }
        if (strlen($enc) !== self::ENC_SIZE) {
            throw new DecryptException('mlkem768x25519 enc must be 1120 bytes');
        }
        if (strlen($stanza->body) !== self::BODY_SIZE) {
            throw new DecryptException('mlkem768x25519 stanza body must be 32 bytes');
        }

        $hpke = self::buildHpke();
        $dk = new DecapsKey(Algorithm::XWing, $this->seed);

        try {
            $ctx = $hpke->setupBaseReceiver($dk, $enc, self::INFO);
            return $ctx->open($stanza->body, '');
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    private static function derivePublicKey(string $seed): string
    {
        $expanded = Keccak::shake256()
            ->absorb($seed)
            ->squeeze(96);

        $d = substr($expanded, 0, 32);
        $z = substr($expanded, 32, 32);
        $skX = substr($expanded, 64, 32);

        $key = Operations::kemKeyGen(3, 2, $d, $z);
        $pkM = $key['encapsulationKeyBytes'];
        $pkX = sodium_crypto_scalarmult_base($skX);

        return $pkM . $pkX;
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
