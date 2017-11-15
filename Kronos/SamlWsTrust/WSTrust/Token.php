<?php

namespace Kronos\SamlWsTrust\WSTrust;

use Kronos\SamlWsTrust\SAML1\SAML1_Assertion;
use SAML2_Assertion;

class Token {

	/**
	 * @var string
	 */
	private $tokenType;

	/**
	 * @var SAML1_Assertion|SAML2_Assertion
	 */
	private $assertion;

	/**
	 * Token constructor.
	 * @param string $token_type
	 * @param SAML1_Assertion|SAML2_Assertion $assertion
	 */
	public function __construct($token_type, $assertion) {

		if(!self::isTokenType($token_type)){
			throw new \InvalidArgumentException('Invalid token_type');
		}

		if(!self::isAssertion($assertion)){
			throw new \InvalidArgumentException('Invalid $assertion');
		}

		$this->tokenType = $token_type;
		$this->assertion = $assertion;
	}

	/**
	 * @return mixed
	 */
	public function getTokenType() {
		return $this->tokenType;
	}

	/**
	 * @param mixed $token_type
	 */
	public function setTokenType($token_type) {
		if(!self::isTokenType($token_type)){
			throw new \InvalidArgumentException('Invalid token_type');
		}

		$this->tokenType = $token_type;
	}

	/**
	 * @return mixed
	 */
	public function getAssertion() {
		return $this->assertion;
	}

	/**
	 * @param mixed $assertion
	 */
	public function setAssertion($assertion) {

		if(!self::isAssertion($assertion)){
			throw new \InvalidArgumentException('Invalid $assertion');
		}

		$this->assertion = $assertion;
	}

	public function getNameId(){
		return $this->getAssertion()->getNameId();
	}

	public function getAttributes(){
		return $this->getAssertion()->getAttributes();
	}

	/**
	 * Get the user identifier in claim $claim_name and fallback on NameId value
	 * @param bool|string $claim_name
	 * @return string
	 */
	public function getIdentifier($claim_name=false){
		$nameId = $this->getNameId();
		$attributes = $this->getAttributes();

		$identifier = '';
		if($nameId){
			$identifier = $nameId['Value'];
		}
		if($claim_name && isset($attributes[$claim_name][0])){
			$identifier = $attributes[$claim_name][0];
		}

		return $identifier;
	}

	public static function isAssertion($assertion){
		return ($assertion instanceof SAML2_Assertion || $assertion instanceof SAML1_Assertion);
	}

	public static function isTokenType($token_type){
		return in_array($token_type, ['SAML_1_1_ENC', "SAML_1_1", 'SAML_2_0', 'SAML_2_0_ENC']);
	}
}

