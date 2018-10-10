<?php

namespace Kronos\Tests\SamlWsTrust\WSTrust;

use Kronos\SamlWsTrust\WSTrust\TokenValidatorResponse;

class TokenValidatorResponseTest extends \PHPUnit_Framework_TestCase
{
    const EMPTY_ERR_MSG = 'Invalid WSTrust token: ';

    const SINGLE_ERR = 'An unknown error occurred';
    const SINGLE_ERR_MSG = self::EMPTY_ERR_MSG . self::SINGLE_ERR;

    const SECOND_ERR = 'Another error occurred';
    const SECOND_ERR_MSG = self::EMPTY_ERR_MSG . self::SINGLE_ERR . ', ' . self::SECOND_ERR;

    /**
     * @var TokenValidatorResponse
     */
    protected $response;

    public function setUp()
    {
        $this->response = new TokenValidatorResponse();
    }

    public function test_Defaults_getValidationErrors_ReturnsEmptyArray()
    {
        $this->assertEquals([], $this->response->getValidationErrors());
    }

    public function test_Defaults_IsValid_ReturnsTrue()
    {
        $this->assertTrue($this->response->isValid());
    }

    public function test_Defaults_GetErrorMessage_ReturnsCorrectString()
    {
        $this->assertSame(self::EMPTY_ERR_MSG, $this->response->getErrorMessage());
    }

    public function test_SingleValidationError_getValidationErrors_ContainsValidationError()
    {
        $this->response->addValidationError(self::SINGLE_ERR_MSG);

        $this->assertContains(self::SINGLE_ERR_MSG, $this->response->getValidationErrors());
    }

    public function test_SingleValidationError_IsValid_ReturnsFalse()
    {
        $this->response->addValidationError('any error');

        $this->assertFalse($this->response->isValid());
    }

    public function test_SingleValidationError_GetErrorMessage_ReturnsCorrectString()
    {
        $this->response->addValidationError(self::SINGLE_ERR);

        $this->assertSame(self::SINGLE_ERR_MSG, $this->response->getErrorMessage());
    }

    public function test_TwoValidationErrors_getValidationErrors_ContainsBothErrors()
    {
        $this->response->addValidationError(self::SINGLE_ERR);
        $this->response->addValidationError(self::SECOND_ERR);

        $this->assertContains(self::SINGLE_ERR, $this->response->getValidationErrors());
        $this->assertContains(self::SECOND_ERR, $this->response->getValidationErrors());
    }

    public function test_TwoValidationErrors_IsValid_ReturnsFalse()
    {
        $this->response->addValidationError(self::SINGLE_ERR);
        $this->response->addValidationError(self::SECOND_ERR);

        $this->assertFalse($this->response->isValid());
    }

    public function test_TwoValidationErrors_GetErrorMessage_ReturnsCorrectString()
    {
        $this->response->addValidationError(self::SINGLE_ERR);
        $this->response->addValidationError(self::SECOND_ERR);

        $this->assertSame(self::SECOND_ERR_MSG, $this->response->getErrorMessage());
    }
}