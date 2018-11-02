<?php

namespace Kronos\SamlWsTrust\WSTrust;

use SAML2\Assertion;

class Token
{

    /**
     * @var string
     */
    private $tokenType = '';

    /**
     * @var Assertion
     */
    private $assertion;

    /**
     * Token constructor.
     * @param string $token_type
     * @param Assertion $assertion
     */
    public function __construct($token_type, $assertion)
    {

        if (!self::isTokenType($token_type)) {
            throw new \InvalidArgumentException('Invalid token_type');
        }

        if (!self::isAssertion($assertion)) {
            throw new \InvalidArgumentException('Invalid $assertion');
        }

        $this->tokenType = $token_type;
        $this->assertion = $assertion;
    }

    /**
     * @return string
     */
    public function getTokenType()
    {
        return $this->tokenType;
    }

    /**
     * @param string $token_type
     */
    public function setTokenType($token_type)
    {
        if (!self::isTokenType($token_type)) {
            throw new \InvalidArgumentException('Invalid token_type');
        }

        $this->tokenType = $token_type;
    }

    /**
     * @return Assertion
     */
    public function getAssertion()
    {
        return $this->assertion;
    }

    /**
     * @param Assertion $assertion
     */
    public function setAssertion($assertion)
    {

        if (!self::isAssertion($assertion)) {
            throw new \InvalidArgumentException('Invalid $assertion');
        }

        $this->assertion = $assertion;
    }

    /**
     * @return \SAML2\XML\saml\NameID|null The name identifier of the assertion.
     * @throws \Exception
     */
    public function getNameId()
    {
        return $this->getAssertion()->getNameId();
    }

    /**
     * @return array
     */
    public function getAttributes()
    {
        return $this->getAssertion()->getAttributes();
    }

    /**
     * Get the user identifier in claim $claim_name and fallback on NameId value
     * @param bool|string $claim_name
     * @return string
     */
    public function getIdentifier($claim_name = false)
    {
        $nameId = $this->getNameId();
        $attributes = $this->getAttributes();

        $identifier = '';
        if ($nameId instanceof \SAML2\XML\saml\NameID) {
            $identifier = $nameId->value;
        }
        if ($claim_name && isset($attributes[$claim_name][0])) {
            $identifier = $attributes[$claim_name][0];
        }

        return $identifier;
    }

    /**
     * @param $assertion
     * @return bool
     */
    public static function isAssertion($assertion)
    {
        return ($assertion instanceof Assertion);
    }

    /**
     * @param $token_type
     * @return bool
     */
    public static function isTokenType($token_type)
    {
        return in_array($token_type, ['SAML_2_0', 'SAML_2_0_ENC']);
    }
}
