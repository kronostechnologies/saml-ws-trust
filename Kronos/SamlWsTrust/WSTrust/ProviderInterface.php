<?php

namespace Kronos\SamlWsTrust\WSTrust;


interface ProviderInterface {

	/**
	 * @return string
	 */
	public function getIdpUrl();

	/**
	 * @return string
	 */
	public function getRpRealm();

	/**
	 * @return array
	 */
	public function getTrustedIssuers();

	/**
	 * @return string[]
	 */
	public function getTrustedCertificates();

	/**
	 * @return ClaimInterface[]
	 */
	public function getMandatoryClaims();
}