<?php
declare(strict_types=1);
namespace Soatok\Age\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Soatok\Age\Age;
use Soatok\Age\Armor;
use Soatok\Age\Exception\AgeException;
use Soatok\Age\Exception\DecryptException;
use Soatok\Age\Exception\ParseException;
use Soatok\Age\Hybrid\Mlkem768X25519\HybridIdentity;
use Soatok\Age\IdentityInterface;
use Soatok\Age\X25519\X25519Identity;
use Throwable;

class CCTVTestVectorTest extends TestCase
{
    /**
     * Skip test vector names that require unimplemented features.
     */
    private const SKIP_PREFIXES = [
        'plugin_',       // Plugin-based recipient types
        'stanza_',       // Generic stanza edge cases
        'scrypt',        // Passphrase-based (not implemented)
    ];

    /** @return array<string, string[]> */
    public static function vectorProvider(): array
    {
        $dir = self::getTestDir();
        if (!is_dir($dir)) {
            return [];
        }
        $cases = [];
        foreach (scandir($dir) as $file) {
            if ($file === '.' || $file === '..') {
                continue;
            }
            $skip = false;
            foreach (self::SKIP_PREFIXES as $prefix) {
                if (str_starts_with($file, $prefix)) {
                    $skip = true;
                    break;
                }
            }
            if (!$skip) {
                $cases[$file] = [$file];
            }
        }
        return $cases;
    }

    #[DataProvider('vectorProvider')]
    public function testVector(string $name): void
    {
        $path = self::getTestDir() . '/' . $name;
        $raw = file_get_contents($path);
        $this->assertNotFalse($raw, "Failed to read $path");

        $vector = self::parseVector($raw);

        // Skip vectors with unknown keys
        if (isset($vector['meta']['unknown_keys'])) {
            $this->markTestSkipped("Unknown keys in vector: $name");
        }

        // Skip vectors for unimplemented recipient types
        if ($this->requiresUnimplementedFeature($vector)) {
            $this->markTestSkipped("Requires unimplemented feature: $name");
        }

        $expect = $vector['meta']['expect'] ?? null;
        $this->assertNotNull($expect, "Missing 'expect' in vector $name");

        $this->runVector($name, $vector, $expect);
    }

    /**
     * @param array{meta: array<string,string|string[]>, age_file: string} $vector
     */
    private function runVector(string $name, array $vector, string $expect): void
    {
        $identities = $this->buildIdentities($vector);
        $ageFile = $vector['age_file'];
        $payloadHash = $vector['meta']['payload'] ?? null;
        $isArmored = ($vector['meta']['armored'] ?? '') === 'yes';

        switch ($expect) {
            case 'success':
                $this->runSuccessVector(
                    $name,
                    $ageFile,
                    $identities,
                    $payloadHash,
                    $isArmored
                );
                break;

            case 'no match':
                $this->runNoMatchVector($name, $ageFile, $identities);
                break;

            case 'HMAC failure':
                $this->runHmacFailureVector($name, $ageFile, $identities);
                break;

            case 'header failure':
                $this->runHeaderFailureVector($name, $ageFile, $identities, $isArmored);
                break;

            case 'payload failure':
                $this->runPayloadFailureVector($name, $ageFile, $identities);
                break;

            case 'armor failure':
                $this->runArmorFailureVector($name, $ageFile);
                break;

            default:
                $this->markTestSkipped("Unknown expect value: $expect");
        }
    }

    private function runSuccessVector(
        string $name,
        string $ageFile,
        array $identities,
        ?string $payloadHash,
        bool $isArmored
    ): void {
        try {
            $plaintext = Age::decrypt($ageFile, $identities);
        } catch (Throwable $e) {
            $this->fail("[$name] Expected success, got: " . $e->getMessage());
        }

        if ($payloadHash !== null) {
            $actual = hash('sha256', $plaintext);
            $this->assertSame(
                $payloadHash,
                $actual,
                "[$name] Payload hash mismatch"
            );
        }
    }

    private function runNoMatchVector(
        string $name,
        string $ageFile,
        array $identities
    ): void {
        try {
            Age::decrypt($ageFile, $identities);
            $this->fail("[$name] Expected 'no match', but decryption succeeded");
        } catch (DecryptException $e) {
            $this->assertStringContainsString(
                'No identity matched',
                $e->getMessage(),
                "[$name] Expected 'no match' error"
            );
        } catch (ParseException) {
            // Also acceptable: parsing the stanza reveals it's invalid
            $this->assertTrue(true);
        }
    }

    private function runHmacFailureVector(
        string $name,
        string $ageFile,
        array $identities
    ): void {
        try {
            Age::decrypt($ageFile, $identities);
            $this->fail("[$name] Expected HMAC failure, but decryption succeeded");
        } catch (DecryptException $e) {
            // HMAC failure should be caught
            $this->assertTrue(true, "[$name] HMAC failure detected");
        } catch (ParseException) {
            // May also manifest as a parse error
            $this->assertTrue(true);
        }
    }

    private function runHeaderFailureVector(
        string $name,
        string $ageFile,
        array $identities,
        bool $isArmored
    ): void {
        try {
            Age::decrypt($ageFile, $identities);
            $this->fail(
                "[$name] Expected header failure, but decryption succeeded"
            );
        } catch (DecryptException|ParseException|AgeException|\SodiumException) {
            $this->assertTrue(true, "[$name] Header failure detected");
        }
    }

    private function runPayloadFailureVector(string $name, string $ageFile, array $identities): void
    {
        try {
            Age::decrypt($ageFile, $identities);
            $this->fail(
                "[$name] Expected payload failure, but decryption succeeded"
            );
        } catch (DecryptException) {
            $this->assertTrue(true, "[$name] Payload failure detected");
        } catch (ParseException) {
            $this->assertTrue(true, "[$name] Parse error during payload");
        }
    }

    private function runArmorFailureVector(
        string $name,
        string $ageFile
    ): void {
        try {
            Armor::decode($ageFile);
            $this->fail("[$name] Expected armor failure, but decode succeeded");
        } catch (ParseException) {
            $this->assertTrue(true, "[$name] Armor failure detected");
        }
    }

    /**
     * @return IdentityInterface[]
     */
    private function buildIdentities(array $vector): array
    {
        $ids = [];
        $identityStrings = $vector['meta']['identity'] ?? [];
        if (is_string($identityStrings)) {
            $identityStrings = [$identityStrings];
        }
        foreach ($identityStrings as $s) {
            $upper = strtoupper($s);
            if (str_starts_with($upper, 'AGE-SECRET-KEY-PQ-')) {
                $ids[] = HybridIdentity::fromString($s);
            } elseif (str_starts_with($upper, 'AGE-SECRET-KEY-1')) {
                $ids[] = X25519Identity::fromString($s);
            }
        }

        return $ids;
    }

    private function requiresUnimplementedFeature(array $vector): bool
    {
        // Passphrase/scrypt not implemented
        if (!empty($vector['meta']['passphrase'])) {
            return true;
        }
        return false;
    }

    /**
     * Parse a CCTV test vector file
     *
     * @return array{meta: array<string,string|list<string>>, age_file: string}
     */
    private static function parseVector(string $raw): array
    {
        $raw = str_replace("\r\n", "\n", $raw);
        $headerEnd = strpos($raw, "\n\n");
        if ($headerEnd === false) {
            throw new RuntimeException('No blank line found in vector');
        }

        $metaSection = substr($raw, 0, $headerEnd);
        $ageFile = substr($raw, $headerEnd + 2);

        // Handle zlib compression
        $meta = self::parseMeta($metaSection);
        if (($meta['compressed'] ?? '') === 'zlib') {
            $decompressed = @gzuncompress($ageFile);
            if ($decompressed === false) {
                $decompressed = @gzinflate($ageFile);
            }
            if ($decompressed === false) {
                throw new RuntimeException('Failed to decompress zlib data');
            }
            $ageFile = $decompressed;
        }

        return ['meta' => $meta, 'age_file' => $ageFile];
    }

    /**
     * @return array<string,string|list<string>>
     */
    private static function parseMeta(string $section): array
    {
        $meta = [];
        foreach (explode("\n", $section) as $line) {
            $colonPos = strpos($line, ': ');
            if ($colonPos === false) {
                continue;
            }
            $key = substr($line, 0, $colonPos);
            $value = substr($line, $colonPos + 2);
            if (in_array($key, ['identity', 'passphrase'], true)) {
                if (!isset($meta[$key])) {
                    $meta[$key] = [];
                }
                $meta[$key][] = $value;
            } else {
                $meta[$key] = $value;
            }
        }
        return $meta;
    }

    public static function getTestDir(): string
    {
        $env = getenv('CCTV_TESTDATA_DIR');
        if (!empty($env) && is_dir($env)) {
            return $env;
        }
        if (!is_dir(dirname(__DIR__ . '/data'))) {
            mkdir(dirname(__DIR__ . '/data'));
        }
        return __DIR__ . '/data';
    }
}
