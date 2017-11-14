<?php

namespace Kronos\SamlWsTrust\WSTrust;


interface ClaimInterface {

	/**
	 * @return string
	 */
	public function getName();

	/**
	 * @return mixed[]
	 */
	public function getValues();
}