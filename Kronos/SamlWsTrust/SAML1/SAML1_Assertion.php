<?php

namespace Kronos\SamlWsTrust\SAML1;

use DOMNode;
use DOMXPath;
use SAML2_Utils;
use XMLSecurityKey;

/**
 * SAML1.1 Token response
 */
class SAML1_Assertion
{
    
    const SAML_ASSERT_NS = 'urn:oasis:names:tc:SAML:1.0:assertion';
    
    /**
     *
     * @var DOMNode
     */
    private $assertNode;
    
    /**
     *
     * @var DOMXpath
     */
    private $xPath;
    
    /**
     * x509 signature certificates
     * @var array
     */
    private $certificates = array();
    
    private $signatureData = null;

    /**
     * SAML1_Assertion constructor.
     * @param DOMNode $assert_node
     */
    public function __construct(DOMNode $assert_node)
    {

        $this->assertNode = $assert_node;
        $dom = $assert_node->ownerDocument;

        $this->xPath = new DOMXpath($dom);
        $this->xPath->registerNamespace('saml1', self::SAML_ASSERT_NS);
        
        $signatureData = SAML1_Util::validateElement($this->assertNode);
        if ($signatureData) {
            $this->signatureData = $signatureData;
            $this->certificates = $this->signatureData['Certificates'];
        }
    }

    /**
     * The issuer or false if not found
     * @return string|bool
     */
    public function getIssuer()
    {
        $query = './@Issuer';
        $nodelist = $this->xPath->query($query, $this->assertNode);
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
    public function getId()
    {
        $query = './@AssertionID';
        $nodelist = $this->xPath->query($query, $this->assertNode);
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
    public function getNameId()
    {
        $query = './saml:AttributeStatement/saml1:Subject/saml1:NameIdentifier';
        $nodelist = $this->xPath->query($query, $this->assertNode);
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
    public function getIssueInstant()
    {
        $query = './@IssueInstant';
        $nodelist = $this->xPath->query($query, $this->assertNode);
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
    public function getNotBefore()
    {
        $query = './saml1:Conditions/@NotBefore';
        $nodelist = $this->xPath->query($query, $this->assertNode);
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
    public function getNotOnOrAfter()
    {
        $query = './saml1:Conditions/@NotOnOrAfter';
        $nodelist = $this->xPath->query($query, $this->assertNode);
        if ($attr = $nodelist->item(0)) {
            return SAML2_Utils::xsDateTimeToTimestamp($attr->value);
        } else {
            return false;
        }
    }

    /**
     * @return array
     */
    public function getValidAudiences()
    {
        $audiences = array();
        
        $query = './saml1:Conditions/saml1:AudienceRestrictionCondition/saml1:Audience';
        $nodelist = $this->xPath->query($query, $this->assertNode);
        foreach ($nodelist as $node) {
            $audiences[] = $node->textContent;
        }
        
        return $audiences;
    }

    /**
     * @return array
     * @throws Exception
     */
    public function getAttributes()
    {
        $attributes = array();
        
        $query = './saml:AttributeStatement/saml:Attribute';

        $nodelist = $this->xPath->query($query, $this->assertNode);
        foreach ($nodelist as $node) {
            $attrib_name = $node->getAttribute('AttributeName');
            $attrib_namespace = $node->getAttribute('AttributeNamespace');
            
            if ($attrib_namespace) {
                $attrib_name = $attrib_namespace . '/' . $attrib_name;
            }
            
            $subNodelist = $this->xPath->query('./saml:AttributeValue', $node);
            if ($subNode = $subNodelist->item(0)) {
                $attrib_value = $subNode->textContent;
            } else {
                throw new Exception('Could not find AttributeValue for ' . $attrib_name);
            }
            
            if (!isset($attributes[$attrib_name])) {
                $attributes[$attrib_name] = array();
            }
            
            $attributes[$attrib_name][] = $attrib_value;
        }
        
        return $attributes;
    }

    /**
     * @return array
     */
    public function getCertificates()
    {
        return $this->certificates;
    }

    /**
     * @param XMLSecurityKey $key
     * @return bool
     */
    public function validate(XMLSecurityKey $key)
    {
        if ($this->signatureData === null) {
            return false;
        }

        SAML2_Utils::validateSignature($this->signatureData, $key);
        return true;
    }
}
