<?php
declare(strict_types=1);
namespace Soatok\Age\Tests;

use PHPUnit\Framework\TestCase;
use Soatok\Age\Age;
use Soatok\Age\X25519\X25519Identity;

class InteropTest extends TestCase
{
    private static function ageBinary(): string
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('age not installed on windows currently');
        }
        $path = trim(shell_exec('which age 2>/dev/null') ?: '');
        if ($path === '' || !is_executable($path)) {
            self::markTestSkipped('age CLI not found');
        }
        return $path;
    }

    /**
     * Go encrypts, PHP decrypts (X25519)
     */
    public function testGoEncryptPhpDecryptX25519(): void
    {
        $age = self::ageBinary();
        $identity = X25519Identity::generate();
        $recipientStr = $identity->getRecipient()->encode();
        $plaintext = 'Go encrypts, PHP decrypts!';

        $inFile = self::writeTmp($plaintext);
        $outFile = tempnam(sys_get_temp_dir(), 'age_out_');

        $cmd = sprintf(
            '%s -e -r %s -o %s %s 2>&1',
            escapeshellarg($age),
            escapeshellarg($recipientStr),
            escapeshellarg($outFile),
            escapeshellarg($inFile)
        );
        exec($cmd, $output, $exitCode);
        unlink($inFile);

        $this->assertSame(0, $exitCode, "age encrypt: " . implode("\n", $output));
        $encrypted = file_get_contents($outFile);
        unlink($outFile);

        $decrypted = Age::decrypt($encrypted, [$identity]);
        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * PHP encrypts, Go decrypts (X25519)
     */
    public function testPhpEncryptGoDecryptX25519(): void
    {
        $age = self::ageBinary();
        $identity = X25519Identity::generate();
        $plaintext = 'PHP encrypts, Go decrypts!';
        $encrypted = Age::encrypt($plaintext, [$identity->getRecipient()]);

        $encFile = self::writeTmp($encrypted);
        $keyFile = self::writeTmp($identity->encode() . "\n");

        $cmd = sprintf(
            '%s -d -i %s %s 2>&1',
            escapeshellarg($age),
            escapeshellarg($keyFile),
            escapeshellarg($encFile)
        );
        $decrypted = shell_exec($cmd);
        unlink($encFile);
        unlink($keyFile);

        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * PHP encrypts armored, Go decrypts
     */
    public function testPhpArmoredGoDecrypt(): void
    {
        $age = self::ageBinary();
        $identity = X25519Identity::generate();
        $plaintext = 'PHP armored, Go decrypts!';
        $encrypted = Age::encryptArmored($plaintext, [$identity->getRecipient()]);

        $encFile = self::writeTmp($encrypted);
        $keyFile = self::writeTmp($identity->encode() . "\n");

        $cmd = sprintf(
            '%s -d -i %s %s 2>&1',
            escapeshellarg($age),
            escapeshellarg($keyFile),
            escapeshellarg($encFile)
        );
        $decrypted = shell_exec($cmd);
        unlink($encFile);
        unlink($keyFile);

        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * Multi-chunk (200 KiB), PHP encrypts, Go decrypts
     */
    public function testLargePayloadPhpToGo(): void
    {
        $age = self::ageBinary();
        $identity = X25519Identity::generate();
        $plaintext = random_bytes(200 * 1024);
        $encrypted = Age::encrypt($plaintext, [$identity->getRecipient()]);

        $encFile = self::writeTmp($encrypted);
        $keyFile = self::writeTmp($identity->encode() . "\n");
        $outFile = tempnam(sys_get_temp_dir(), 'age_out_');

        $cmd = sprintf(
            '%s -d -i %s -o %s %s 2>&1',
            escapeshellarg($age),
            escapeshellarg($keyFile),
            escapeshellarg($outFile),
            escapeshellarg($encFile)
        );
        exec($cmd, $output, $exitCode);
        unlink($encFile);
        unlink($keyFile);

        $this->assertSame(0, $exitCode, "age decrypt: " . implode("\n", $output));
        $decrypted = file_get_contents($outFile);
        unlink($outFile);

        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * Multi-chunk (200 KiB), Go encrypts, PHP decrypts.
     */
    public function testLargePayloadGoToPhp(): void
    {
        $age = self::ageBinary();
        $identity = X25519Identity::generate();
        $recipientStr = $identity->getRecipient()->encode();
        $plaintext = random_bytes(200 * 1024);

        $inFile = self::writeTmp($plaintext);
        $outFile = tempnam(sys_get_temp_dir(), 'age_out_');

        $cmd = sprintf(
            '%s -e -r %s -o %s %s 2>&1',
            escapeshellarg($age),
            escapeshellarg($recipientStr),
            escapeshellarg($outFile),
            escapeshellarg($inFile)
        );
        exec($cmd, $output, $exitCode);
        unlink($inFile);

        $this->assertSame(0, $exitCode, "age encrypt: " . implode("\n", $output));
        $encrypted = file_get_contents($outFile);
        unlink($outFile);

        $decrypted = Age::decrypt($encrypted, [$identity]);
        $this->assertSame($plaintext, $decrypted);
    }

    private static function writeTmp(string $data): string
    {
        $path = tempnam(sys_get_temp_dir(), 'age_');
        file_put_contents($path, $data);
        return $path;
    }
}
