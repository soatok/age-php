<?php
declare(strict_types=1);
namespace Soatok\Age;

use ParagonIE\ConstantTime\Base64;

final class Stanza
{
    public const LINE_LENGTH = 64;

    /**
     * @param string $type
     * @param string[] $args
     * @param string $body
     */
    public function __construct(
        public readonly string $type,
        public readonly array $args,
        public readonly string $body,
    ) {}

    public function serialize(): string
    {
        $out = '-> ' . $this->type;
        foreach ($this->args as $arg) {
            $out .= ' ' . $arg;
        }
        $out .= "\n";
        $out .= self::wrapBase64(Base64::encodeUnpadded($this->body));
        return $out;
    }

    private static function wrapBase64(string $b64): string
    {
        if ($b64 === '') {
            return "\n";
        }
        $out = chunk_split($b64, self::LINE_LENGTH, "\n");
        $len = strlen($b64);
        if ($len % 64 === 0) {
            $out .= "\n";
        }
        return $out;
    }
}
