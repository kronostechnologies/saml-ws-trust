<?php

namespace  Kronos\SamlWsTrust\WSTrust;

class TokenValidatorResponse {

	private $_validation_errors = [];

	function __construct(){
	}

	public function addValidationError($error_message){
		$this->_validation_errors[] = $error_message;
	}

	public function isValid(){
		return count($this->_validation_errors) === 0;
	}

	public function getErrorMessage(){
		return 'Invalid WSTrust token: ' . implode(', ', $this->_validation_errors);
	}

	public function getValidationErrors(){
		return $this->_validation_errors;
	}
}