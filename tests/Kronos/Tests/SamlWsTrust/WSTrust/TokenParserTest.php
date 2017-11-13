<?php

namespace Kronos\Tests\SamlWsTrust\WSTrust;

use Kronos\SamlWsTrust\SAML1\SAML1_Assertion;
use Kronos\SamlWsTrust\WSTrust\Token;
use Kronos\SamlWsTrust\WSTrust\TokenParser,  DOMXPath;
use SAML2_Assertion;

class TokenParserTest extends \PHPUnit_Framework_TestCase {

	/**
	 * @var TestableTokenParer
	 */
	private $parser;
	private $assertion;

	public function test_SAML11TokenParser_Parse_WillReturnSAML11Token() {
		$this->setupParser('SAML_1_1_ENC', SAML1_Assertion::class);

		$token = $this->parser->parseToken(self::A_XML);

		$this->assertInstanceOf(Token::class, $token);
		$this->assertEquals('SAML_1_1_ENC', $token->getTokenType());
	}

	public function test_SAML20TokenParser_Parse_WillReturnSAML20Token() {
		$this->setupParser('SAML_2_0', SAML2_Assertion::class);

		$token = $this->parser->parseToken(self::A_XML);

		$this->assertInstanceOf(Token::class, $token);
		$this->assertEquals('SAML_2_0', $token->getTokenType());
	}

	public function test_EncryptedSAML20TokenParser_Parse_WillReturnSAML20Token() {
		$this->setupParser('SAML_2_0_ENC', SAML2_Assertion::class);

		$token = $this->parser->parseToken(self::A_XML);

		$this->assertInstanceOf(Token::class, $token);
		$this->assertEquals('SAML_2_0_ENC', $token->getTokenType());
	}

	public function test_TokenParser_Parse_WillReturnTokenWithParsedAssertion() {
		$this->setupParser('SAML_1_1_ENC', SAML1_Assertion::class);

		$token = $this->parser->parseToken(self::A_XML);

		$assertion = $token->getAssertion();

		$this->assertEquals($assertion, $this->assertion, 'getAssertion() match mock assertion');
	}

	public function test_TokenParserWithInvalidType_Construct_WillThrowInvalidArgumentException() {
		$this->setExpectedException('\InvalidArgumentException');
		$this->setupParser(self::INVALID_TOKEN_TYPE, SAML1_Assertion::class);
	}


	private function setupParser($token_type, $assertion_class_name){
		$this->assertion = $this->getMockBuilder($assertion_class_name)->disableOriginalConstructor()->getMock();
		$this->parser = new TestableTokenParer($token_type);
		$this->parser->_setMockAssertion($this->assertion);
	}

	const A_XML = '<xml></xml>';
	const INVALID_TOKEN_TYPE = 'SAML99999';

}

/**
 * Token parser use SimpleSAMLPhp with lot of dependency and config that cannot be easily testable.
 */
class TestableTokenParer extends TokenParser {

	private $_mock_assertion;

	public function _setMockAssertion($assertion){
		$this->_mock_assertion = $assertion;
	}

	protected function parseEncryptedSAML1Assertion(DOMXpath $xpath){
		return $this->_mock_assertion;
	}

	protected function parseSAML2Assertion(DOMXpath $xpath){
		return $this->_mock_assertion;
	}

	protected function parseEncryptedSAML2Assertion(DOMXpath $xpath){
		return $this->_mock_assertion;
	}
}