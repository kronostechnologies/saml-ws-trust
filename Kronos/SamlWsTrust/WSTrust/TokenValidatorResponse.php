<?php

namespace  Kronos\SamlWsTrust\WSTrust;

class TokenValidatorResponse {

	private $_validation_errors = [];

	/**
	 * @param string $error_message
	 */
	public function addValidationError($error_message){
		$this->_validation_errors[] = $error_message;
	}

	/**
	 * @return bool
	 */
	public function isValid(){
		return count($this->_validation_errors) === 0;
	}

	/**
	 * @return string
	 */
	public function getErrorMessage(){
		return 'Invalid WSTrust token: ' . implode(', ', $this->_validation_errors);
	}

	/**
	 * @return string[]
	 */
	public function getValidationErrors(){
		return $this->_validation_errors;
	}
}