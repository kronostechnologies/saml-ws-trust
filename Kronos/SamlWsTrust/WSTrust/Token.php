<?php

namespace Kronos\SamlWsTrust\WSTrust;

use SAML2\Assertion;
use SAML2\XML\saml\NameID;

class Token
{
    private string $tokenType;

    private Assertion $assertion;

    /**
     * @var string Initial decryted token data compressed with gzdeflate and encoded in base64
     */
    private string $deflateEncodedAssertion;

    /**
     * Token constructor.
     * @param string $token_type
     * @param Assertion $assertion
     * @param string $deflateEncodedAssertion Initial decryted token data compressed with gzdeflate and encoded in base64
     */
    public function __construct(string $token_type, Assertion $assertion, string $deflateEncodedAssertion)
    {
        if (!self::isTokenType($token_type)) {
            throw new \InvalidArgumentException('Invalid token_type');
        }

        $this->tokenType = $token_type;
        $this->assertion = $assertion;
        $this->deflateEncodedAssertion = $deflateEncodedAssertion;
    }

    public function getTokenType(): string
    {
        return $this->tokenType;
    }

    /**
     * @param string $token_type
     */
    public function setTokenType(string $token_type)
    {
        if (!self::isTokenType($token_type)) {
            throw new \InvalidArgumentException('Invalid token_type');
        }

        $this->tokenType = $token_type;
    }

    public function getAssertion(): Assertion
    {
        return $this->assertion;
    }

    /**
     * @param Assertion $assertion
     */
    public function setAssertion(Assertion $assertion)
    {
        $this->assertion = $assertion;
    }

    /**
     * @return NameID|null The name identifier of the assertion.
     * @throws \Exception
     */
    public function getNameId(): ?NameID
    {
        return $this->getAssertion()->getNameId();
    }

    /**
     * @return array
     */
    public function getAttributes(): array
    {
        return $this->getAssertion()->getAttributes();
    }

    /**
     * Get the user identifier in claim $claim_name and fallback on NameId value
     * @param ?string $claim_name
     * @return ?string
     */
    public function getIdentifier(string $claim_name = null): ?string
    {
        $nameId = $this->getNameId();
        $attributes = $this->getAttributes();

        $identifier = null;
        if ($nameId instanceof NameID) {
            $identifier = $nameId->getValue();
        }
        if ($claim_name && isset($attributes[$claim_name][0])) {
            /** @var ?string $identifier */
            $identifier = $attributes[$claim_name][0] ?? null;
        }

        return $identifier;
    }

    /**
     * @param string $token_type
     */
    public static function isTokenType($token_type): bool
    {
        return in_array($token_type, ['SAML_2_0', 'SAML_2_0_ENC']);
    }

    public function getDeflateEncodedAssertion(): string
    {
        return $this->deflateEncodedAssertion;
    }
}
