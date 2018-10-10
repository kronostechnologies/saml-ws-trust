<?php

namespace Kronos\Tests\SamlWsTrust\WSTrust;

use Kronos\SamlWsTrust\SAML1\SAML1_Assertion;
use Kronos\SamlWsTrust\WSTrust\Token;
use SAML2_Assertion;
use SAML2_EncryptedAssertion;

class TokenTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @var Token
     */
    private $token;
    private $assertion;
    private $assertion_nameId;
    private $assertion_attributes;

    public function test_Saml20Token_getNameId_WillReturnAssertionNameId()
    {
        $this->givenSAML2Token();

        $returnedNameId = $this->token->getNameId();

        $this->assertEquals($this->assertion_nameId, $returnedNameId);
    }

    public function test_Saml20Token_getAttributes_WillReturnAssertionAttributes()
    {
        $this->givenSAML2Token();

        $returnedAttributes = $this->token->getAttributes();

        $this->assertEquals($this->assertion_attributes, $returnedAttributes);
    }


    public function test_SAML1Token_getNameId_WillReturnAssertionNameId()
    {
        $this->givenSAML1Token();

        $returnedNameId = $this->token->getNameId();

        $this->assertEquals($this->assertion_nameId, $returnedNameId);
    }

    public function test_SAML1Token_getAttributes_WillReturnAssertionAttributes()
    {
        $this->givenSAML1Token();

        $returnedAttributes = $this->token->getAttributes();

        $this->assertEquals($this->assertion_attributes, $returnedAttributes);
    }

    public function test_Token_getIdentifierWithoutClaimName_WillReturnNameIdValue()
    {
        $this->givenSAML2Token();

        $returnedIdentifier = $this->token->getIdentifier();

        $this->assertEquals(self::AN_IDENTIFIER, $returnedIdentifier);
    }

    public function test_Token_getIdentifierWithClaimName_WillReturnNameIdValue()
    {
        $this->givenSAML2Token();

        $returnedIdentifier = $this->token->getIdentifier(self::AN_IDENTIFIER_CLAIM_NAME);

        $this->assertEquals(self::AN_IDENTIFIER_CLAIM_VALUE, $returnedIdentifier);
    }

    public function test_Token_ConstructWithInvalidToken_WillThrowInvalidArgumentException()
    {
        $this->setupAssertion(SAML2_Assertion::class);
        $this->expectException(\InvalidArgumentException::class);

        $token = new Token(self::AN_INVALID_TOKEN_TYPE, $this->assertion);
    }

    public function test_Token_ConstructWithInvalidAssertionType_WillThrowInvalidArgumentException()
    {
        $this->givenInvalidAssertionType();
        $this->expectException(\InvalidArgumentException::class);

        $token = new Token(self::AN_INVALID_TOKEN_TYPE, $this->assertion);
    }

    public function test_Token_ConstructWithValidTokenTypes_ReturnsTokenInstance()
    {
        $this->setupAssertion(SAML1_Assertion::class);

        foreach (self::VALID_TOKEN_TYPES as $validTokenType) {
            try {
                $token = new Token($validTokenType, $this->assertion);

                $this->assertInstanceOf(Token::class, $token);
            } catch (\Exception $e) {
                $this->assertFalse(true, "{$validTokenType} is not a valid token type anymore.");
            }
        }
    }

    public function test_Token_ConstructWithValidAssertion_ReturnsTokenInstance()
    {
        $this->setupAssertion(SAML1_Assertion::class);

        try {
            $token = new Token(self::VALID_TOKEN_TYPES[0], $this->assertion);

            $this->assertInstanceOf(Token::class, $token);
        } catch (\Exception $e) {
            $this->assertFalse(true, "Assertion check failed.");
        }
    }

    public function test_Token_ConstructWithInvalidAssertion_ThrowsException()
    {
        $this->assertion = new \stdClass();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid $assertion');

        new Token(self::VALID_TOKEN_TYPES[0], $this->assertion);
    }

    public function test_Token_SetValidTokenType_Succeeds()
    {
        $this->setupAssertion(SAML1_Assertion::class);
        $token = new Token(self::VALID_TOKEN_TYPES[0], $this->assertion);

        foreach (self::VALID_TOKEN_TYPES as $validTokenType) {
            try {
                $token->setTokenType($validTokenType);

                $this->assertTrue(true);
            } catch (\Exception $e) {
                $this->assertFalse(true, "{$validTokenType} is not a valid token type anymore.");
            }
        }
    }

    public function test_Token_SetInvalidTokenType_ThrowsInvalidArgumentException()
    {
        $this->setupAssertion(SAML1_Assertion::class);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid token_type');

        new Token(self::AN_INVALID_TOKEN_TYPE, $this->assertion);
    }

    public function test_Token_SetValidAssertion_Succeeds()
    {
        $this->setupAssertion(SAML1_Assertion::class);
        $token = new Token(self::VALID_TOKEN_TYPES[0], $this->assertion);

        try {
            $token->setAssertion($this->assertion);

            $this->assertTrue(true);
        } catch (\Exception $e) {
            $this->assertFalse(true, "Assertion check failed.");
        }
    }

    public function test_Token_SetInvalidAssertion_ThrowsInvalidArgumentException()
    {
        $this->setupAssertion(SAML1_Assertion::class);
        $token = new Token(self::VALID_TOKEN_TYPES[0], $this->assertion);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid $assertion');

        $token->setAssertion(new \stdClass());
    }


    private function givenInvalidAssertionType()
    {
        $this->assertion = $this->getMockBuilder(SAML2_EncryptedAssertion::class)->disableOriginalConstructor()->getMock();
    }

    private function givenSAML2Token()
    {
        $this->setupAssertion(SAML2_Assertion::class);
        $this->token = new Token('SAML_2_0', $this->assertion);
    }

    private function givenSAML1Token()
    {
        $this->setupAssertion(SAML1_Assertion::class);
        $this->token = new Token('SAML_1_1_ENC', $this->assertion);
    }

    private function setupAssertion($assertion_class_name)
    {
        $this->assertion_nameId = ['Value' => self::AN_IDENTIFIER];
        $this->assertion_attributes = [
            self::AN_IDENTIFIER_CLAIM_NAME => [
                self::AN_IDENTIFIER_CLAIM_VALUE
            ]
        ];

        $this->assertion = $this->getMockBuilder($assertion_class_name)->disableOriginalConstructor()->getMock();
        $this->assertion->method('getNameId')->willReturn($this->assertion_nameId);
        $this->assertion->method('getAttributes')->willReturn($this->assertion_attributes);

    }

    const VALID_TOKEN_TYPES = ['SAML_1_1', 'SAML_1_1_ENC', 'SAML_2_0', 'SAML_2_0_ENC'];

    const AN_IDENTIFIER = 'asdf@asdf.com';
    const AN_IDENTIFIER_CLAIM_NAME = 'user-id';
    const AN_IDENTIFIER_CLAIM_VALUE = 'asdf222@asdf.com';
    const AN_INVALID_TOKEN_TYPE = 'bad bad bad';
}