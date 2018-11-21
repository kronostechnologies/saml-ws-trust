<?php

namespace Kronos\Tests\SamlWsTrust\WSTrust;

use Kronos\SamlWsTrust\WSTrust\Token;
use Kronos\SamlWsTrust\WSTrust\TokenParser;
use Kronos\Tests\SamlWsTrust\TestCase;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class TokenParserTest extends TestCase {
	const MOCKS_PATH = __DIR__ . '/../../../Mocks/';

	const VALID_SAML_20_RTSP_FILE = self::MOCKS_PATH . 'ValidSAML20RTSP.xml';
	const VALID_SAML_20_CRYPT_RTSP_FILE = self::MOCKS_PATH . 'ValidSAML20CryptRTSP.xml';
	const VALID_SAML_20_CRYPT_RTSP_DECRYPTED_ASSERTION_FILE = self::MOCKS_PATH . 'ValidSAML20CryptRTSPDecryptedAssertion.xml';
    const SAML_20_MANY_ASSERT_FILE = self::MOCKS_PATH . 'SAML20ManyAssertions.xml';
    const SAML_20_NO_ASSERT_FILE = self::MOCKS_PATH . 'SAML20NoAssertion.xml';
    const SAML_20_ENC_MANY_ASSERT_FILE = self::MOCKS_PATH . 'SAML20EncManyAssertions.xml';
    const SAML_20_ENC_NO_ASSERT_FILE = self::MOCKS_PATH . 'SAML20EncNoAssertion.xml';
    const INPUT_KEY_FILE = self::MOCKS_PATH . 'InputKey.key';
    const INPUT_KEY_PASSPHRASE = 'asdf';

    const INVALID_TOKEN_TYPE = 'SAML99999';

    // Enforce constants here, not in code!
    const VALID_TOKEN_TYPES = ['SAML_2_0', 'SAML_2_0_ENC'];

    const DEFLATE_ENCODED_SAML2_ASSERTION = 'fVHBaoQwFLzvV0juMWpbKA8Vlu5F6BaKSw+9ZfVtTTFR8pKyn99obWsXtnMJ5E1m5k1ykrqHLRFapwYTnXVvCKbLgnlrYJCkCIzUSOAaqLf7R8jiBOT3CxZVu0D1quVyAT8G8CaAtwEcVwh0Io+VISeNK1iWpPc8yXh6d0gzSG8gvX1l0QtaCtphHCes3EQr5HPg2h/fsXF/R7/jp5C32kXT8exlr04KbcHqQ81KH3JP6+Rixbyms9g8DOakrJZzQ3t03dD+306jgdC0aPnH4JsOiYmLLcT1Nb6s55ps2Tk3Egih2jHGs9Rjj/Fg38RklS0qC3VzIf7zqeUn';
    const DEFLATE_ENCODED_SAML2_CRYPT_ASSERTION = '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';

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
    protected function getValidSAML20CryptRTSP()
    {
        return file_get_contents(self::VALID_SAML_20_CRYPT_RTSP_FILE);
    }

    /**
     * @return string
     */
    protected function getValidSAML20CryptRTSPDecryptedAssertion()
    {
        return trim(file_get_contents(self::VALID_SAML_20_CRYPT_RTSP_DECRYPTED_ASSERTION_FILE));
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

    private function getInputKey(){
        $inputKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'private'));
        $inputKey->passphrase = self::INPUT_KEY_PASSPHRASE;
        $inputKey->loadKey(self::INPUT_KEY_FILE, true);
        return $inputKey;
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

    public function test_ValidSAML20RSTP_parseToken_TokenInstanceContainsDeflateEncodedAssertion()
    {
        $parser = new TokenParser('SAML_2_0');

        $retVal = $parser->parseToken($this->getValidSAML20RTSP());

//        $plain = gzinflate(base64_decode($retVal->getDeflateEncodedAssertion()));
        $this->assertEquals(self::DEFLATE_ENCODED_SAML2_ASSERTION, $retVal->getDeflateEncodedAssertion());
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

    public function test_ValidSAML20CryptRSTP_parseToken_ReturnsTokenInstance()
    {
        $parser = new TokenParser('SAML_2_0_ENC');
        $parser->setInputKey($this->getInputKey());

        $retVal = $parser->parseToken($this->getValidSAML20CryptRTSP());

        $this->assertInstanceOf(Token::class, $retVal);
    }

    public function test_ValidSAML20CryptRSTP_parseToken_TokenInstanceContainsAssertion()
    {
        $parser = new TokenParser('SAML_2_0_ENC');
        $parser->setInputKey($this->getInputKey());

        $retVal = $parser->parseToken($this->getValidSAML20CryptRTSP());

        $this->assertInstanceOf(\SAML2_Assertion::class, $retVal->getAssertion());
    }

    public function test_ValidSAML20CryptRSTP_parseToken_TokenInstanceContainsDeflateEncodedAssertion()
    {
        $parser = new TokenParser('SAML_2_0_ENC');
        $parser->setInputKey($this->getInputKey());

        $retVal = $parser->parseToken($this->getValidSAML20CryptRTSP());

        $decryptedAssertion = gzinflate(base64_decode($retVal->getDeflateEncodedAssertion()));

        $this->assertEquals($this->getValidSAML20CryptRTSPDecryptedAssertion(), $decryptedAssertion);
        $this->assertEquals(self::DEFLATE_ENCODED_SAML2_CRYPT_ASSERTION, $retVal->getDeflateEncodedAssertion());
    }
}
