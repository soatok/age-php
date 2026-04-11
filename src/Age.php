<?php
declare(strict_types=1);
namespace Soatok\Age;

use Random\RandomException;
use SensitiveParameter;
use Soatok\Age\Exception\AgeException;
use Soatok\Age\Exception\DecryptException;

final class Age
{
    private const FILE_KEY_SIZE = 16;

    /**
     * @param string $plaintext
     * @param RecipientInterface[] $recipients
     * @return string
     *
     * @throws AgeException
     * @throws RandomException
     */
    public static function encrypt(
        #[SensitiveParameter]
        string $plaintext,
        array $recipients
    ): string {
        if (empty($recipients)) {
            throw new AgeException('At least one recipient is required');
        }
        return self::encryptWithFileKey(
            $plaintext,
            $recipients,
            random_bytes(self::FILE_KEY_SIZE)
        );
    }

    /**
     * @param string $plaintext
     * @param RecipientInterface[] $recipients
     * @param string $fileKey
     * @return string
     *
     * @throws RandomException
     */
    public static function encryptWithFileKey(
        #[SensitiveParameter]
        string $plaintext,
        array $recipients,
        #[SensitiveParameter]
        string $fileKey
    ): string {
        $stanzas = self::wrapFileKey($fileKey, $recipients);
        $header = Header::create($stanzas, $fileKey);
        $payload = Payload::encrypt($fileKey, $plaintext);
        return $header->serialize() . $payload;
    }

    /**
     * @param IdentityInterface[] $identities
     * @return string Decrypted plaintext
     *
     * @throws DecryptException
     */
    public static function decrypt(string $ageFile, array $identities): string
    {
        if (empty($identities)) {
            throw new AgeException('At least one identity is required');
        }
        $data = self::maybeDearmor($ageFile);
        ['header' => $header, 'offset' => $payloadOffset] = Header::parse($data);
        self::validateScryptExclusivity($header);
        $fileKey = self::unwrapFileKey($header->stanzas, $identities);
        $header->verifyMac($fileKey);
        $payload = substr($data, $payloadOffset);
        return Payload::decrypt($fileKey, $payload);
    }

    /**
     * @param string $plaintext
     * @param array $recipients
     * @return string
     *
     * @throws RandomException
     */
    public static function encryptArmored(
        #[SensitiveParameter]
        string $plaintext,
        array $recipients
    ): string {
        return Armor::encode(self::encrypt($plaintext, $recipients));
    }

    private static function maybeDearmor(string $data): string
    {
        $trimmed = ltrim($data);
        if (str_starts_with($trimmed, '-----BEGIN AGE ENCRYPTED FILE')) {
            return Armor::decode($data);
        }
        return $data;
    }

    /**
     * @param RecipientInterface[] $recipients
     * @return Stanza[]
     */
    private static function wrapFileKey(
        #[SensitiveParameter]
        string $fileKey,
        array $recipients
    ): array {
        $stanzas = [];
        foreach ($recipients as $recipient) {
            foreach ($recipient->wrap($fileKey) as $stanza) {
                $stanzas[] = $stanza;
            }
        }
        return $stanzas;
    }

    /**
     * @param Stanza[] $stanzas
     * @param IdentityInterface[] $identities
     *
     * @throws DecryptException
     */
    private static function unwrapFileKey(array $stanzas, array $identities): string
    {
        foreach ($identities as $identity) {
            foreach ($stanzas as $stanza) {
                $fileKey = $identity->unwrap($stanza);
                if ($fileKey !== null) {
                    return $fileKey;
                }
            }
        }
        throw new DecryptException('No identity matched any recipient stanza');
    }

    /**
     * @throws DecryptException
     */
    private static function validateScryptExclusivity(Header $header): void
    {
        $hasScrypt = false;
        foreach ($header->stanzas as $stanza) {
            if ($stanza->type === 'scrypt') {
                $hasScrypt = true;
                break;
            }
        }

        if ($hasScrypt && count($header->stanzas) > 1) {
            throw new DecryptException('scrypt stanza must be the only stanza in the header');
        }
    }
}
