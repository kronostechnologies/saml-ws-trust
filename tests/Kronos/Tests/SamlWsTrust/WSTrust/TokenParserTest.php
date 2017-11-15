<?php

namespace Kronos\Tests\SamlWsTrust\WSTrust;

use Kronos\SamlWsTrust\WSTrust\TokenParser;

class TokenParserTest extends \PHPUnit_Framework_TestCase {

	/**
	 * @var TokenParser
	 */
	private $parser;
	private $assertion;

	public function test_TokenParserWithInvalidType_Construct_WillThrowInvalidArgumentException() {
		$this->setExpectedException('\InvalidArgumentException');

		new TokenParser(self::INVALID_TOKEN_TYPE);
	}

	const INVALID_TOKEN_TYPE = 'SAML99999';

}