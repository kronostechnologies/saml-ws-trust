<?php

namespace Kronos\Tests\SamlWsTrust\WSTrust;

use Kronos\SamlWsTrust\WSTrust\Token;
use Kronos\SamlWsTrust\WSTrust\TokenParser;
use Kronos\Tests\SamlWsTrust\TestCase;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class TokenParserTest extends TestCase {
	const MOCKS_PATH = __DIR__ . '/../../../Mocks/';

	const VALID_SAML_20_RTSP_FILE = self::MOCKS_PATH . 'ValidSAML20RTSP.xml';
    const SAML_20_MANY_ASSERT_FILE = self::MOCKS_PATH . 'SAML20ManyAssertions.xml';
    const SAML_20_NO_ASSERT_FILE = self::MOCKS_PATH . 'SAML20NoAssertion.xml';

    const SAML_20_ENC_MANY_ASSERT_FILE = self::MOCKS_PATH . 'SAML20EncManyAssertions.xml';
    const SAML_20_ENC_NO_ASSERT_FILE = self::MOCKS_PATH . 'SAML20EncNoAssertion.xml';

    const INVALID_TOKEN_TYPE = 'SAML99999';

    // Enforce constants here, not in code!
    const VALID_TOKEN_TYPES = ['SAML_2_0', 'SAML_2_0_ENC'];

    /**
     * @return string
     */
    protected function getValidSAML20RTSP()
    {
        return file_get_contents(self::VALID_SAML_20_RTSP_FILE);
    }

    /**
     * @return string
     */
    protected function getSAML20ManyAssertions()
    {
        return file_get_contents(self::SAML_20_MANY_ASSERT_FILE);
    }

    /**
     * @return string
     */
    protected function getSAML20NoAssertion()
    {
        return file_get_contents(self::SAML_20_NO_ASSERT_FILE);
    }

    /**
     * @return string
     */
    protected function getSAML20EncManyAssertions()
    {
        return file_get_contents(self::SAML_20_ENC_MANY_ASSERT_FILE);
    }

    /**
     * @return string
     */
    protected function getSAML20EncNoAssertion()
    {
        return file_get_contents(self::SAML_20_ENC_NO_ASSERT_FILE);
    }

    public function test_TokenParserWithInvalidType_Construct_WillThrowInvalidArgumentException() {
		$this->setExpectedException('\InvalidArgumentException');

		new TokenParser(self::INVALID_TOKEN_TYPE);
	}

	public function test_TokenParserWithValidType_Construct_WillInstanciateSuccessfully()
    {
        foreach (self::VALID_TOKEN_TYPES as $validTokenType) {
            try {
                $retVal = new TokenParser($validTokenType);

                $this->assertInstanceOf(TokenParser::class, $retVal);
            } catch (\Exception $e) {
                $this->assertFalse(true, "{$validTokenType} is not a valid token type anymore.");
            }
        }
    }

    public function test_ValidSAML20RSTP_parseToken_ReturnsTokenInstance()
    {
        $parser = new TokenParser('SAML_2_0');

        $retVal = $parser->parseToken($this->getValidSAML20RTSP());

        $this->assertInstanceOf(Token::class, $retVal);
    }

    public function test_SAML20ManyAssertions_parseToken_ThrowsException()
    {
        $parser = new TokenParser('SAML_2_0');

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Only one assertion element supported.');

        $parser->parseToken($this->getSAML20ManyAssertions());
    }

    public function test_SAML20NoAssertion_parseToken_ThrowsException()
    {
        $parser = new TokenParser('SAML_2_0');

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('No assertion found element supported.');

        $parser->parseToken($this->getSAML20NoAssertion());
    }

    public function test_NonXMLDocument_parseToken_ThrowsException()
    {
        $parser = new TokenParser('SAML_2_0');

        $this->expectException(\PHPUnit_Framework_Error_Warning::class);

        $parser->parseToken("non xml doc");
    }

    public function test_ValidSAML20RSTP_parseToken_TokenInstanceContainsAssertion()
    {
        $parser = new TokenParser('SAML_2_0');

        $retVal = $parser->parseToken($this->getValidSAML20RTSP());

        $this->assertInstanceOf(\SAML2_Assertion::class, $retVal->getAssertion());
    }

    public function test_UnencryptedSAML20RSTPNoInputKey_parseToken_ThrowsException()
    {
        $parser = new TokenParser('SAML_2_0_ENC');

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Unable to parse encrypted token without input key');

        $parser->parseToken($this->getValidSAML20RTSP());
    }

    public function test_SAML20EncManyAssertions_parseToken_ThrowsException()
    {
        $parser = new TokenParser('SAML_2_0_ENC');
        $parser->setInputKey(new XMLSecurityKey(XMLSecurityKey::TRIPLEDES_CBC));

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Only one assertion element supported.');

        $parser->parseToken($this->getSAML20EncManyAssertions());
    }

    public function test_SAML20EncNoAssertion_parseToken_ThrowsException()
    {
        $parser = new TokenParser('SAML_2_0_ENC');
        $parser->setInputKey(new XMLSecurityKey(XMLSecurityKey::TRIPLEDES_CBC));

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('No assertion found element supported.');

        $parser->parseToken($this->getSAML20EncNoAssertion());
    }
}
