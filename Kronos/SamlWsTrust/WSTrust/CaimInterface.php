<?php

namespace Kronos\SamlWsTrust\WSTrust;


interface CaimInterface {

	/**
	 * @return string
	 */
	public function getName();

	/**
	 * @return mixed[]
	 */
	public function getValues();
}