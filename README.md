# age-php

[![CI](https://github.com/soatok/age-php/actions/workflows/ci.yml/badge.svg)](https://github.com/soatok/age-php/actions/workflows/ci.yml)

PHP implementation of [age](https://c2sp.org/age). Supports post-quantum cryptography.

> [!TIP]
> The author pronounces it `[aɡe̞]` [with a hard *g*](https://translate.google.com/?sl=it&text=aghe), like GIF, and it's 
always spelled lowercase.

## Installation

```shell
composer require soatok/age
```

## Usage

We ecommend using **Hybrid ML-KEM-768 + X25519** for identities and recipients.

```php
<?php
use Soatok\Age\Age;
use Soatok\Age\Hybrid\Mlkem768X25519\{
    HybridIdentity,
    HybridRecipient
};

// Generate a new identity for Alice:
$alice = HybridIdentity::generate();

// You can use HybridRecipient::fromString(/* age public key goes here */); to load a public key
// For a runnable example, we generate Bob's on-the-fly:
$bobSecret = HybridIdentity::generate(); 
$bob = $bobSecret->getRecipient();

// Sample encryption:
$aliceToBob = Age::encrypt('hello bob', [$bob]);
// Example decryption:
$bobReads = Age::decrypt($aliceToBob, [$bobSecret]);
var_dump($bobReads); // string(9) "hello bob"

// With optional ASCII armor:
$bobToAlice = Age::encryptArmored('hi alice!', [$alice->getRecipient()]);
$aliceReads = Age::decrypt($bobToAlice, [$alice]);
var_dump($aliceReads); // string(9) "hi alice!"
```

## Limitations

* P-256 is currently not implemented
  * Nor is Hybrid ML-KEM-768 + P-256
* Scrypt is not supported

## License

This PHP port of age is released under the same 3-Clause BSD license as [the Go implementation](https://github.com/filosottile/age).
