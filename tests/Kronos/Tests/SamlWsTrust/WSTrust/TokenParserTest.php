<?php

namespace Kronos\Tests\SamlWsTrust\WSTrust;

use Kronos\SamlWsTrust\WSTrust\Token;
use Kronos\SamlWsTrust\WSTrust\TokenParser;

class TokenParserTest extends \PHPUnit_Framework_TestCase {

	/**
	 * @var TokenParser
	 */
	private $parser;
	private $assertion;

	const MOCKS_PATH = __DIR__ . '/../../../Mocks/';
	const VALID_SAML_11_RTSP_FILE = self::MOCKS_PATH . 'ValidSAML11RTSP.xml';
    const SAML_11_MANY_ASSERT_FILE = self::MOCKS_PATH . 'SAML11ManyAssertions.xml';
	const SAML_11_NO_ASSERT_FILE = self::MOCKS_PATH . 'SAML11NoAssertion.xml';

	const VALID_SAML_20_RTSP_FILE = self::MOCKS_PATH . 'ValidSAML20RTSP.xml';
    const SAML_20_MANY_ASSERT_FILE = self::MOCKS_PATH . 'SAML20ManyAssertions.xml';
    const SAML_20_NO_ASSERT_FILE = self::MOCKS_PATH . 'SAML20NoAssertion.xml';

    const INVALID_TOKEN_TYPE = 'SAML99999';

    // Enforce constants here, not in code!
    const VALID_TOKEN_TYPES = ['SAML_1_1', 'SAML_1_1_ENC', 'SAML_2_0', 'SAML_2_0_ENC'];

    /**
     * @return string
     */
    protected function getValidSAML11RTSP()
    {
        return file_get_contents(self::VALID_SAML_11_RTSP_FILE);
    }

    /**
     * @return string
     */
    protected function getSAML11ManyAssertions()
    {
        return file_get_contents(self::SAML_11_MANY_ASSERT_FILE);
    }

    /**
     * @return string
     */
    protected function getSAML11NoAssertion()
    {
        return file_get_contents(self::SAML_11_NO_ASSERT_FILE);
    }

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

    public function test_ValidSAML11RTSP_parseToken_ReturnsTokenInstance()
    {
        $parser = new TokenParser('SAML_1_1');

        $retVal = $parser->parseToken($this->getValidSAML11RTSP());

        $this->assertInstanceOf(Token::class, $retVal);
    }

    public function test_SAML11ManyAssertions_parseToken_ThrowsException()
    {
        $parser = new TokenParser('SAML_1_1');

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Only one assertion element supported.');

        $parser->parseToken($this->getSAML11ManyAssertions());
    }

    public function test_SAML11NoAssertion_parseToken_ThrowsException()
    {
        $parser = new TokenParser('SAML_1_1');

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('No assertion found element supported.');

        $parser->parseToken($this->getSAML11NoAssertion());
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
}