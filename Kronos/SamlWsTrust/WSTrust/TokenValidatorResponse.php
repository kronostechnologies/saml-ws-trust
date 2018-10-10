<?php

namespace  Kronos\SamlWsTrust\WSTrust;

class TokenValidatorResponse
{

    private $validatorErrors = [];

    /**
     * @param string $error_message
     */
    public function addValidationError($error_message)
    {
        $this->validatorErrors[] = $error_message;
    }

    /**
     * @return bool
     */
    public function isValid()
    {
        return count($this->validatorErrors) === 0;
    }

    /**
     * @return string
     */
    public function getErrorMessage()
    {
        return 'Invalid WSTrust token: ' . implode(', ', $this->validatorErrors);
    }

    /**
     * @return string[]
     */
    public function getValidationErrors()
    {
        return $this->validatorErrors;
    }
}
