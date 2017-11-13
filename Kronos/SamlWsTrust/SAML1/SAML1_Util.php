<?php

namespace Kronos\SamlWsTrust\SAML1;


use DOMDocument;
use DOMNode;
use SAML2_Utils;
use XMLSecurityDSig;

class SAML1_Util {

	/**
	 * Check the Signature in a XML element.
	 *
	 * Taken from SAML2_Utils::validateElement but modified to support SAML1.1
	 */
	public static function validateElement(DOMNode $root)
	{
		/* Create an XML security object. */
		$objXMLSecDSig = new XMLSecurityDSig();

		/* Both SAML messages and SAML assertions use the 'ID' attribute. */
		$objXMLSecDSig->idKeys[] = 'AssertionID';

		/* Locate the XMLDSig Signature element to be used. */
		$signatureElement = SAML2_Utils::xpQuery($root, './ds:Signature');
		if (count($signatureElement) === 0) {
			/* We don't have a signature element ot validate. */

			return FALSE;
		} elseif (count($signatureElement) > 1) {
			throw new Exception('XMLSec: more than one signature element in root.');
		}
		$signatureElement = $signatureElement[0];
		$objXMLSecDSig->sigNode = $signatureElement;

		/* Canonicalize the XMLDSig SignedInfo element in the message. */
		$objXMLSecDSig->canonicalizeSignedInfo();

		/* Validate referenced xml nodes. */
		if (!$objXMLSecDSig->validateReference()) {
			throw new Exception('XMLsec: digest validation failed');
		}

		/* Check that $root is one of the signed nodes. */
		$rootSigned = FALSE;
		/** @var DOMNode $signedNode */
		foreach ($objXMLSecDSig->getValidatedNodes() as $signedNode) {
			if ($signedNode->isSameNode($root)) {
				$rootSigned = TRUE;
				break;
			} elseif ($root->parentNode instanceof DOMDocument && $signedNode->isSameNode($root->ownerDocument)) {
				/* $root is the root element of a signed document. */
				$rootSigned = TRUE;
				break;
			}
		}
		if (!$rootSigned) {
			throw new Exception('XMLSec: The root element is not signed.');
		}

		/* Now we extract all available X509 certificates in the signature element. */
		$certificates = array();
		foreach (SAML2_Utils::xpQuery($signatureElement, './ds:KeyInfo/ds:X509Data/ds:X509Certificate') as $certNode) {
			$certData = trim($certNode->textContent);
			$certData = str_replace(array("\r", "\n", "\t", ' '), '', $certData);
			$certificates[] = $certData;
		}

		$ret = array(
			'Signature' => $objXMLSecDSig,
			'Certificates' => $certificates,
		);

		return $ret;
	}
}