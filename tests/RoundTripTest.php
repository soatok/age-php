<?php
declare(strict_types=1);
namespace Soatok\Age\Tests;

use PHPUnit\Framework\TestCase;
use Soatok\Age\Age;
use Soatok\Age\Bech32;
use Soatok\Age\Header;
use Soatok\Age\Payload;
use Soatok\Age\X25519\X25519Identity;
use Soatok\Age\X25519\X25519Recipient;

class RoundTripTest extends TestCase
{
    public function testBech32RoundTrip(): void
    {
        $data = random_bytes(32);
        $encoded = Bech32::encode('age', $data);
        $decoded = Bech32::decode($encoded);
        $this->assertSame('age', $decoded['hrp']);
        $this->assertSame($data, $decoded['data']);
    }

    public function testBech32SecretKeyRoundTrip(): void
    {
        $data = random_bytes(32);
        $encoded = strtoupper(Bech32::encode('age-secret-key-', $data));
        $this->assertStringStartsWith('AGE-SECRET-KEY-1', $encoded);
        $decoded = Bech32::decode(strtolower($encoded));
        $this->assertSame('age-secret-key-', $decoded['hrp']);
        $this->assertSame($data, $decoded['data']);
    }

    public function testX25519KeyGeneration(): void
    {
        $identity = X25519Identity::generate();
        $encoded = $identity->encode();
        $this->assertStringStartsWith('AGE-SECRET-KEY-1', $encoded);

        $parsed = X25519Identity::fromString($encoded);
        $this->assertSame($encoded, $parsed->encode());
    }

    public function testX25519RecipientEncoding(): void
    {
        $identity = X25519Identity::generate();
        $recipient = $identity->getRecipient();
        $encoded = $recipient->encode();
        $this->assertStringStartsWith('age1', $encoded);

        $parsed = X25519Recipient::fromString($encoded);
        $this->assertSame($encoded, $parsed->encode());
    }

    public function testX25519EncryptDecrypt(): void
    {
        $identity = X25519Identity::generate();
        $recipient = $identity->getRecipient();

        $plaintext = 'Hello, age!';
        $encrypted = Age::encrypt($plaintext, [$recipient]);
        $decrypted = Age::decrypt($encrypted, [$identity]);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testX25519EmptyPlaintext(): void
    {
        $identity = X25519Identity::generate();
        $recipient = $identity->getRecipient();

        $encrypted = Age::encrypt('', [$recipient]);
        $decrypted = Age::decrypt($encrypted, [$identity]);

        $this->assertSame('', $decrypted);
    }

    public function testX25519LargePlaintext(): void
    {
        $identity = X25519Identity::generate();
        $recipient = $identity->getRecipient();

        // Test with data > 64 KiB (multiple STREAM chunks)
        $plaintext = random_bytes(100_000);
        $encrypted = Age::encrypt($plaintext, [$recipient]);
        $decrypted = Age::decrypt($encrypted, [$identity]);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testMultipleRecipients(): void
    {
        $id1 = X25519Identity::generate();
        $id2 = X25519Identity::generate();

        $plaintext = 'Shared secret';
        $encrypted = Age::encrypt($plaintext, [
            $id1->getRecipient(),
            $id2->getRecipient(),
        ]);

        $this->assertSame($plaintext, Age::decrypt($encrypted, [$id1]));
        $this->assertSame($plaintext, Age::decrypt($encrypted, [$id2]));
    }

    public function testArmoredRoundTrip(): void
    {
        $identity = X25519Identity::generate();
        $recipient = $identity->getRecipient();

        $plaintext = 'Armored content';
        $armored = Age::encryptArmored($plaintext, [$recipient]);

        $this->assertStringContainsString('-----BEGIN AGE ENCRYPTED FILE-----', $armored);

        $decrypted = Age::decrypt($armored, [$identity]);
        $this->assertSame($plaintext, $decrypted);
    }

    public function testHeaderSerializationRoundTrip(): void
    {
        $identity = X25519Identity::generate();
        $recipient = $identity->getRecipient();

        $fileKey = random_bytes(16);
        $stanzas = $recipient->wrap($fileKey);
        $header = Header::create($stanzas, $fileKey);

        $serialized = $header->serialize();
        $parsed = Header::parse($serialized . random_bytes(32));
        $this->assertSame($header->serialize(), $parsed['header']->serialize());
    }

    public function testPayloadRoundTrip(): void
    {
        $fileKey = random_bytes(16);
        $plaintext = 'Test payload encryption';

        $encrypted = Payload::encrypt($fileKey, $plaintext);
        $decrypted = Payload::decrypt($fileKey, $encrypted);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testPayloadChunkBoundary(): void
    {
        $fileKey = random_bytes(16);
        $plaintext = str_repeat('A', Payload::CHUNK_SIZE);
        $decrypted = Payload::decrypt(
            $fileKey,
            Payload::encrypt($fileKey, $plaintext)
        );
        $this->assertSame($plaintext, $decrypted);

        // One full chunk + 1 byte
        $plaintext = str_repeat('B', Payload::CHUNK_SIZE + 1);
        $decrypted = Payload::decrypt($fileKey, Payload::encrypt($fileKey, $plaintext));
        $this->assertSame($plaintext, $decrypted);
    }
}
