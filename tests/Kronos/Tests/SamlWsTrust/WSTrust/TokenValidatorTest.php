<?php

namespace Kronos\Tests\SamlWsTrust\WSTrust;

use Kronos\SamlWsTrust\WSTrust\ClaimInterface;
use Kronos\SamlWsTrust\WSTrust\ProviderInterface;
use Kronos\SamlWsTrust\WSTrust\Token, Kronos\SamlWsTrust\WSTrust\TokenValidator;
use PHPUnit_Framework_MockObject_MockObject;
use SAML2_Assertion;

class TokenValidatorTest extends \PHPUnit_Framework_TestCase {

	/**
	 * @var SAML2_Assertion | PHPUnit_Framework_MockObject_MockObject
	 */
	private $assertion;

	/**
	 * @var ProviderInterface
	 */
	private $provider;

	/**
	 * @var Token | PHPUnit_Framework_MockObject_MockObject
	 */
	private $token;

	/**
	 * @var TokenValidator
	 */
	private $validator;


	public function setUp(){
		$this->assertion = $this->getMockBuilder(SAML2_Assertion::class)->disableOriginalConstructor()->getMock();

		$this->provider = $this->getMock(ProviderInterface::class);
		$this->provider->method('getIdpUrl')->willReturn(self::AN_IDP);
		$this->provider->method('getRpRealm')->willReturn(self::A_REALM);
		$this->provider->method('getTrustedIssuers')->willReturn([self::AN_ISSUER]);
		$this->provider->method('getTrustedCertificates')->willReturn([self::A_X509_CERTIFICATE_FINGERPRINT]);

		$this->validator = new TokenValidator($this->provider);
	}

	public function test_ValidToken_Validate_WillReturnValidResponse(){
		$this->provider->method('getMandatoryClaims')->willReturn([]);
		$this->setupToken();

		$response = $this->validator->validate($this->token);

		$this->assertEquals([], $response->getValidationErrors());
		$this->assertTrue($response->isValid());
	}

	public function test_ValidToken_Validate_WillCallAssertionValidate(){
		$this->provider->method('getMandatoryClaims')->willReturn([]);
		$this->setupToken();
		$this->assertion->expects($this->once())->method('validate');

		$response = $this->validator->validate($this->token);

		$this->assertTrue($response->isValid());
	}

	public function test_TokenWithInvalidAssertionValidate_Validate_WillReturnInvalidResponseWithExceptionMessageAsValidationError(){
		$this->provider->method('getMandatoryClaims')->willReturn([]);
		$this->setupToken();
		$this->assertion->expects($this->once())->method('validate')->willThrowException(new \Exception(self::A_VALIDATE_ERROR_MESSAGE));

		$response = $this->validator->validate($this->token);

		$this->assertFalse($response->isValid());

		// Fragile
		$errors = $response->getValidationErrors();
		$this->assertStringEndsWith(self::A_VALIDATE_ERROR_MESSAGE, $errors[0]);
	}

	public function test_TokenWithBadIssuer_Validate_WillReturnInvalidResponse(){
		$this->provider->method('getMandatoryClaims')->willReturn([]);
		$this->setupToken([
				'issuer' => self::AN_OTHER_ISSUER]
		);

		$response = $this->validator->validate($this->token);

		$this->assertFalse($response->isValid());
	}

	public function test_TokenWithInvalidAudience_Validate_WillReturnInvalidResponse(){
		$this->provider->method('getMandatoryClaims')->willReturn([]);
		$this->setupToken([
						'audience' => self::AN_OTHER_REALM]
		);

		$response = $this->validator->validate($this->token);

		$this->assertFalse($response->isValid());
	}

	public function test_TokenNotBeforeTime_Validate_WillReturnValidResponse(){
		$this->provider->method('getMandatoryClaims')->willReturn([]);
		$time = time();
		$pastTime = $time - (60); // Token valid une minute ago

		$this->setupToken(['notBefore' => $pastTime]);

		$response = $this->validator->validate($this->token);

		$this->assertEquals([], $response->getValidationErrors());
		$this->assertTrue($response->isValid());
	}

	public function test_TooEarlyToken_Validate_WillReturnInvalidResponse(){
		$this->provider->method('getMandatoryClaims')->willReturn([]);
		$time = time();
		$futureTime = $time + (70 * 60); // 70 minutes because validator accept a 60 minutes gap.

		$this->setupToken(['notBefore' => $futureTime]);

		$response = $this->validator->validate($this->token);

		$this->assertFalse($response->isValid());
	}

	public function test_NotExpiredToken_Validate_WillReturnValidResponse(){
		$this->provider->method('getMandatoryClaims')->willReturn([]);
		$time = time();
		$futureTime = $time + (60); // Now plus one minute

		$this->setupToken(['notOnOrAfter' => $futureTime]);

		$response = $this->validator->validate($this->token);

		$this->assertEquals([], $response->getValidationErrors());
		$this->assertTrue($response->isValid());
	}

	public function test_ExpiredToken_Validate_WillReturnInvalidResponse(){
		$this->provider->method('getMandatoryClaims')->willReturn([]);
		$time = time();
		$pastTime = $time;

		$this->setupToken(['notOnOrAfter' => $pastTime]);

		$response = $this->validator->validate($this->token);

		$this->assertFalse($response->isValid());
	}

	public function test_Token_Validate_WillReturnInvalidResponse(){
		$this->provider->method('getMandatoryClaims')->willReturn([]);
		$time = time();
		$pastTime = $time;

		$this->setupToken(['notOnOrAfter' => $pastTime]);

		$response = $this->validator->validate($this->token);

		$this->assertFalse($response->isValid());
	}

	public function test_TokenContainingValidatorExpectedClaim_Validate_WillReturnValidResponse(){
		$this->givenMandatoryClaim();
		$this->setupToken([
				'attributes' => [
						self::A_CLAIM_NAME => [
							self::A_CLAIM_VALUE
						]
				]
		]);

		$response = $this->validator->validate($this->token);

		$this->assertEquals([], $response->getValidationErrors());
		$this->assertTrue($response->isValid());
	}

	public function test_TokenMissingValidatorExpectedClaim_Validate_WillReturnInvalidResponse(){
		$this->givenMandatoryClaim();
		$this->setupToken();

		$response = $this->validator->validate($this->token);

		$this->assertFalse($response->isValid());
	}

	public function test_TokenWithInvalidValueForValidatorExpectedClaim_Validate_WillReturnInvalidResponse(){
		$this->givenMandatoryClaim();
		$this->setupToken([
				'attributes' => [
						self::A_CLAIM_NAME => [
								self::AN_OTHER_CLAIM_VALUE
						]
				]
		]);

		$response = $this->validator->validate($this->token);

		$this->assertFalse($response->isValid());
	}

	public function test_TokenWithoutX509Certificate_Validate_WillReturnInvalidResponse(){
		$this->provider->method('getMandatoryClaims')->willReturn([]);
		$this->setupToken([
				'certificates' => false
		]);

		$response = $this->validator->validate($this->token);

		$this->assertFalse($response->isValid());
	}

	public function test_TokenWithInvalidX509Certificate_Validate_WillReturnInvalidResponse(){
		$this->provider->method('getMandatoryClaims')->willReturn([]);
		$this->setupToken([
				'certificates' => [self::AN_OTHER_X509_CERTIFICATE]
		]);

		$response = $this->validator->validate($this->token);

		$this->assertFalse($response->isValid());
	}

	private function setupToken(array $overrides = []){

		$issuer = isset($overrides['issuer']) ? $overrides['issuer'] : self::AN_ISSUER;
		$audience = isset($overrides['audience']) ? $overrides['audience'] : self::A_REALM;

		$assertion_attributes = [
				self::AN_IDENTIFIER_CLAIM_NAME => [
						self::AN_IDENTIFIER_CLAIM_VALUE
				]
		];

		if(isset($overrides['attributes'])){
			$assertion_attributes = array_merge($assertion_attributes, $overrides['attributes']);
		}

		if(isset($overrides['certificates'])){
			$certificates = $overrides['certificates'];
		}
		else {
			$certificates = [self::A_X509_CERTIFICATE];
		}


		$assertion_nameId = ['Value' => self::AN_IDENTIFIER];
		$this->assertion->method('getNameId')->willReturn($assertion_nameId);
		$this->assertion->method('getAttributes')->willReturn($assertion_attributes);
		$this->assertion->method('getIssuer')->willReturn($issuer);
		$this->assertion->method('getValidAudiences')->willReturn([$audience]);

		if($certificates){
			$this->assertion->method('getCertificates')->willReturn($certificates);
		}

		if(isset($overrides['notBefore'])){
			$this->assertion->method('getNotBefore')->willReturn($overrides['notBefore']);
		}

		if(isset($overrides['notOnOrAfter'])){
			$this->assertion->method('getNotOnOrAfter')->willReturn($overrides['notOnOrAfter']);
		}

		$this->token = $this->getMockBuilder(Token::class)->disableOriginalConstructor()->getMock();
		$this->token->method('getAssertion')->willReturn($this->assertion);
	}

	private function givenMandatoryClaim(){
		$claim = $this->getMock(ClaimInterface::class);
		$claim->method('getName')->willReturn(self::A_CLAIM_NAME);
		$claim->method('getValues')->willReturn([self::A_CLAIM_VALUE]);
		$this->provider->method('getMandatoryClaims')->willReturn([$claim]);
	}

	const AN_IDP = 'https://auth.somedomain.com/idp';
	const A_REALM = 'http://secure.com';
	const AN_OTHER_REALM = 'http://invalid.com';
	const AN_ISSUER = 'https://auth.somedomain.com/issuer';
	const AN_OTHER_ISSUER = 'https://auth.some-other-domain.com/issuer';
	const AN_IDENTIFIER= 'asdf@asdf.com';
	const AN_IDENTIFIER_CLAIM_NAME= 'user-id';
	const AN_IDENTIFIER_CLAIM_VALUE= 'asdf222@asdf.com';
	const AN_INVALID_TOKEN_TYPE = 'bad bad bad';
	const A_CLAIM_NAME = 'ROLES';
	const A_CLAIM_VALUE = 'MYROLE';
	const AN_OTHER_CLAIM_VALUE = 'INVALIDROLE';
	const A_VALIDATE_ERROR_MESSAGE = 'Invalid assertion';

	const A_X509_CERTIFICATE = 'MIIFKjCCAxICCQD73aedGVh50TANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJDQTELMAkGA1UECAwCUUMxDzANBgNVBAoMBktyb25vczEqMCgGA1UEAwwhcG9jLXNzby5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE0MTExOTE1NDQxMloXDTE1MTExOTE1NDQxMlowVzELMAkGA1UEBhMCQ0ExCzAJBgNVBAgMAlFDMQ8wDQYDVQQKDAZLcm9ub3MxKjAoBgNVBAMMIXBvYy1zc28uYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMQcKoYFWXpcqVNsxlJ1CAus7049W1nNYxXUrhLeowKHitWIgWPWApMc1QaJLQ5EBGRVGbgEPACi7Blu14k1wmwvPspOfBA1VaOjXdinN7wO7bT5EbnG7slhki0g+j+mBoHFK6uhWJZK+Ats1KiniazMmVH4zDn0r777c4CIWXJQ+4NcW3W9mxI5d1FJkzJ6BCriYSl7J/ung+BBRdNxRrhmoBbI3ohgKyk9dBAO67+3XRvZYk46OmZGL1ULxKXesxKnrFv055SkZEM0x/bo+Rh3bAwusLxHAKOFryoxlTA2Jc1BYD+1hAmTk7IAtZfKZrSvDQpVEymsqlMy81ZfwwtilyhH9QoKG47qHbJhnc8f9w1g6qL1XICuDURxpuxkrsU6XgntOqV41A/SMlJSz+drPFlTvKBJx5eJcXTu7hf5JQ1KUIUET5hOyCA9nJn4lK9Bmi+9nd4Mj4ixJdkXMFsZgQSHMLKSbTYu3uBxWpzEDW6n2mNIMEq4JsR2/j07IoQEMERcCeW3N/mYIF+CSxJFHx/4RKKV5LRoyzYfb9dAtAKQKhBKADYNj/zPuldoBHNM2zI8tdBuEfNHfuM69rYNY9fmR7qdDoIgZnIDxpSWeKJH5iJaGDU2M9+MUGfSCQihEYZytfj0m4FKvVolDbgcoB0cHL8mpvrKYY9aEGaJAgMBAAEwDQYJKoZIhvcNAQELBQADggIBABViW1snG8CJz+6lIKqWH6pMPGW8iJB/EuGSLvE3bMBkUQq/R7b5SrFD8UpE0rU/+NuJplDRhj6QPTzeTsZt23vGK0yEnnDc5f6GoSm2JZSEgYjSZXAEkvqkpGMuK6EaeA6/wu7vxMZl/Bi/KdBLsONkkAhJwXPWdDXMBWrq4bAkOqXUfNCcJB5metqEs+F2X0zQrjnaPvFan1MDCzkvOS5DsU+g00u4toqLxcfPSvvSt3qVKV42nHF9G92SpdYUpHI/4KAeoU1SOhIrJnhIIGMQKfpowj2/8rLyqq5zeBJlZroHfOJK55AozGVf8s5h8sU+B1vfkCj9L3xzrQBJzFDGb+Ow/WuxM2BdAQvJdzPYuqE3bU8crRZtUBK9v59qJRHhSIprD93hfUXDEvpqcwcp0kZBusgjIkYUBYYUWdJ0NWPFwwIw+HE2zoNEkKjEbqF3a+/FAPtzOpUFaRcZ8LPRule1O9X8fWG1MEnHN9HUQbAzIDM+3wGH0Zemxzipfl3yqOJ4qjOb2n1OPl9uF+l0dJE4j2w7gJ/+ZqSS2pdHtQaFsPTGfWSTrYRfwuIpFokTGJGuJSvOasCF3BzqIj8XKFfyOCZ7AfcGf2b4HXq+E/LLIZ7SbIzgW1IjmV8C57Hpt1H0/gqlFxp1vLJPS7I8PV4Zvh7zEwVrTDM0JxR9';
	const A_X509_CERTIFICATE_FINGERPRINT = '811dd35cf44fff53cf7c1160b443d8eb5f0fae15';
	const AN_OTHER_X509_CERTIFICATE = 'MIIFKjCCAxICCQD73aedGVh50TANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJDQTELMAkGA1UECAwCUUMxDzANBgNVBAoMBktyb25vczEqMCgGA1UEAwwhcG9jLXNzby5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE0MTExOTE1NDQxMloXDTE1MTExOTE1NDQxMlowVzELMAkGA1UEBhMCQ0ExCzAJBgNVBAgMAlFDMQ8wDQYDVQQKDAZLcm9ub3MxKjAoBgNVBAMMIXBvYy1zc28uYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMQcKoYFWXpcqVNsxlJ1CAus7049W1nNYxXUrhLeowKHitWIgWPWApMc1QaJLQ5EBGRVGbgEPACi7Blu14k1wmwvPspOfBA1VaOjXdinN7wO7bT5EbnG7slhki0g+j+mBoHFK6uhWJZK+Ats1KiniazMmVH4zDn0r777c4CIWXJQ+4NcW3W9mxI5d1FJkzJ6BCriYSl7J/ung+BBRdNxRrhmoBbI3ohgKyk9dBAO67+3XRvZYk46OmZGL1ULxKXesxKnrFv055SkZEM0x/bo+Rh3bAwusLxHAKOFryoxlTA2Jc1BYD+1hAmTk7IAtZfKZrSvDQpVEymsqlMy81ZfwwtilyhH9QoKG47qHbJhnc8f9w1g6qL1XICuDURxpuxkrsU6XgntOqV41A/SMlJSz+drPFlTvKBJx5eJcXTu7hf5JQ1KUIUET5hOyCA9nJn4lK9Bmi+9nd4Mj4ixJdkXMFsZgQSHMLKSbTYu3uBxWpzEDW6n2mNIMEq4JsR2/j07IoQEMERcCeW3N/mYIF+CSxJFHx/4RKKV5LRoyzYfb9dAtAKQKhBKADYNj/zPuldoBHNM2zI8tdBuEfNHfuM69rYNY9fmR7qdDoIgZnIDxpSWeKJH5iJaGDU2M9+MUGfSCQihEYZytfj0m4FKvVolDbgcoB0cHL8mpvrKYY9aEGaJAgMBAAEwDQYJKoZIhvcNAQELBQADggIBABViW1snG8CJz+6lIKqWH6pMPGW8iJB/EuGSLvE3bMBkUQq/R7b5SrFD8UpE0rU/+NuJplDRhj6QPTzeTsZt23vGK0yEnnDc5f6GoSm2JZSEgYjSZXAEkvqkpGMuK6EaeA6/wu7vxMZl/Bi/KdBLsONkkAhJwXPWdDXMBWrq4bAkOqXUfNCcJB5metqEs+F2X0zQrjnaPvFan1MDCzkvOS5DsU+g00u4toqLxcfPSvvSt3qVKV42nHF9G92SpdYUpHI/4KAeoU1SOhIrJnhIIGMQKfpowj2/8rLyqq5zeBJlZroHfOJK55AozGVf8s5h8sU+B1vfkCj9L3xzrQBJzFDGb+Ow/WuxM2BdAQvJdzPYuqE3bU8crRZtUBK9v59qJRHhSIprD93hfUXDEvpqcwcp0kZBusgjIkYUBYYUWdJ0NWPFwwIw+HE2zoNEkKjEbqF3a+/FAPtzOpUFaRcZ8LPRule1O9X8fWG1MEnHN9HUQbAzIDM+3wGH0Zemxzipfl3yqOJ4qjOb2n1OPl9uF+l0dJE4j2w7gJ/+ZqSS2pdHtQaFsPTGfWSTrYRfwuIpFokTGJGuJSvOasCF3BzqIj8XKFfyOCZ7AfcGf2b4HXq+E/LLIZ7SbIzgW1IjmV8C57Hpt1H0/gqlFxp1vLJPS7I8PV4Zvh7zEwVrTDM0JxRZ';


}