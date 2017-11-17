<?php

namespace Kronos\SamlWsTrust\SAML1;

use DOMNode;
use DOMXPath;
use XMLSecurityKey, SAML2_Utils;

/**
 * SAML1.1 Token response
 */
class SAML1_Assertion {
	
	const SAML_ASSERT_NS = 'urn:oasis:names:tc:SAML:1.0:assertion';
	
	/**
	 *
	 * @var DOMNode
	 */
	private $_assert_node;
	
	/**
	 *
	 * @var DOMXpath
	 */
	private $_xpath;
	
	/**
	 * x509 signature certificates
	 * @var array
	 */
	private $_certificates = array();
	
	private $_signatureData = null;

	/**
	 * SAML1_Assertion constructor.
	 * @param DOMNode $assert_node
	 */
	public function __construct(DOMNode $assert_node){

		$this->_assert_node = $assert_node;
		$dom = $assert_node->ownerDocument;

		$this->_xpath = new DOMXpath($dom);
		$this->_xpath->registerNamespace('saml1', self::SAML_ASSERT_NS);
		
		$signatureData = SAML1_Util::validateElement($this->_assert_node);
		if($signatureData){
			$this->_signatureData = $signatureData;
			$this->_certificates = $this->_signatureData['Certificates'];
		}
	}

	/**
	 * The issuer or false if not found
	 * @return string|bool
	 */
	public function getIssuer(){
		$query = './@Issuer';
		$nodelist = $this->_xpath->query($query, $this->_assert_node);
		if ($attr = $nodelist->item(0)) {
			return $attr->value;
		} else {
			return false;
		}
	}

	/**
	 * The id or false if not found
	 * @return string|bool
	 */
	public function getId(){
		$query = './@AssertionID';
		$nodelist = $this->_xpath->query($query, $this->_assert_node);
		if ($attr = $nodelist->item(0)) {
			return $attr->value;
		} else {
			return false;
		}
	}

	/**
	 * The name identifier value or false if not found
	 * @return array|bool
	 */
	public function getNameId(){
		$query = './saml:AttributeStatement/saml1:Subject/saml1:NameIdentifier';
		$nodelist = $this->_xpath->query($query, $this->_assert_node);
		if ($attr = $nodelist->item(0)) {
			// Respect simplesamlphp interface.
			return array('Value' => $attr->textContent);
		} else {
			return false;
		}
	}

	/**
	 * The issue instant timestamp or false if not found
	 * @return string|bool
	 */
	public function getIssueInstant(){
		$query = './@IssueInstant';
		$nodelist = $this->_xpath->query($query, $this->_assert_node);
		if ($attr = $nodelist->item(0)) {
			return SAML2_Utils::xsDateTimeToTimestamp($attr->value);
		} else {
			return false;
		}
	}

	/**
	 * The value as timestamp or false if not found
	 *
	 * @return string|bool
	 */
	public function getNotBefore(){
		$query = './saml1:Conditions/@NotBefore';
		$nodelist = $this->_xpath->query($query, $this->_assert_node);
		if ($attr = $nodelist->item(0)) {
			return SAML2_Utils::xsDateTimeToTimestamp($attr->value);
		} else {
			return false;
		}
	}

	/**
	 * The value as timestamp or false if not found
	 *
	 * @return string|bool
	 */
	public function getNotOnOrAfter(){
		$query = './saml1:Conditions/@NotOnOrAfter';
		$nodelist = $this->_xpath->query($query, $this->_assert_node);
		if ($attr = $nodelist->item(0)) {
			return SAML2_Utils::xsDateTimeToTimestamp($attr->value);
		} else {
			return false;
		}
	}

	/**
	 * @return array
	 */
	public function getValidAudiences(){
		$audiences = array();
		
		$query = './saml1:Conditions/saml1:AudienceRestrictionCondition/saml1:Audience';
		$nodelist = $this->_xpath->query($query, $this->_assert_node);
		foreach($nodelist as $node){
			$audiences[] = $node->textContent;
		}
		
		return $audiences;
	}

	/**
	 * @return array
	 * @throws Exception
	 */
	public function getAttributes(){
		$attributes = array();
		
		$query = './saml:AttributeStatement/saml:Attribute';

		$nodelist = $this->_xpath->query($query, $this->_assert_node);
		foreach($nodelist as $node){
			$attrib_name = $node->getAttribute('AttributeName');
			$attrib_namespace = $node->getAttribute('AttributeNamespace');
			
			if($attrib_namespace){
				$attrib_name = $attrib_namespace . '/' . $attrib_name;
			}
			
			$subNodelist = $this->_xpath->query('./saml:AttributeValue', $node);
			if ($subNode = $subNodelist->item(0)) {
				$attrib_value = $subNode->textContent;
			} else {
				throw new Exception('Could not find AttributeValue for ' . $attrib_name);
			}
			
			if(!isset($attributes[$attrib_name])){
				$attributes[$attrib_name] = array();
			}
			
			$attributes[$attrib_name][] = $attrib_value;
		}
		
		return $attributes;
	}

	/**
	 * @return array
	 */
	public function getCertificates(){
		return $this->_certificates;
	}

	/**
	 * @param XMLSecurityKey $key
	 * @return bool
	 */
	public function validate(XMLSecurityKey $key) {
        if ($this->_signatureData === null) {
            return false;
        }

        SAML2_Utils::validateSignature($this->_signatureData, $key);
        return true;
    }
}