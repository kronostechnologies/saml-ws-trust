<?php

namespace Kronos\SamlWsTrust\WSTrust;

use DOMDocument;
use DOMXPath;
use Kronos\SamlWsTrust\SAML1\SAML1_Assertion;
use SAML2_Assertion;
use SAML2_Utils;
use XMLSecurityKey;

class TokenParser
{

    /**
     * @var string
     */
    private $tokenType;

    /**
     * @var XMLSecurityKey
     */
    private $inputKey;

    /**
     * TokenParser constructor.
     * @param string $token_type
     */
    public function __construct($token_type)
    {
        if (!Token::isTokenType($token_type)) {
            throw new \InvalidArgumentException('Invalid $token_type');
        }

        $this->tokenType = $token_type;
    }

    /**
     * @param $token_xml
     * @return Token
     * @throws Exception
     */
    public function parseToken($token_xml)
    {

        $dom = new DOMDocument();
        $token_xml = str_replace('\"', '"', $token_xml);
        $dom->loadXML(str_replace("\r", "", $token_xml));

        $xpath = new \DOMXpath($dom);
        $xpath->registerNamespace('wst', 'http://schemas.xmlsoap.org/ws/2005/02/trust');
        $xpath->registerNamespace('trust', 'http://docs.oasis-open.org/ws-sx/ws-trust/200512');
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
        $xpath->registerNamespace('saml1', 'urn:oasis:names:tc:SAML:1.0:assertion');

        switch ($this->tokenType) {
            case 'SAML_1_1':
                $assertion = $this->parseSAML1Assertion($xpath);
                break;
            case 'SAML_1_1_ENC':
                $assertion = $this->parseEncryptedSAML1Assertion($xpath);
                break;
            case 'SAML_2_0':
                $assertion = $this->parseSAML2Assertion($xpath);
                break;
            case 'SAML_2_0_ENC':
                $assertion = $this->parseEncryptedSAML2Assertion($xpath);
                break;
            default:
                throw new  \DomainException('Invalid token type: ' . $this->tokenType);
        }

        return new Token($this->tokenType, $assertion);
    }

    /**
     * @param XMLSecurityKey $input_key
     */
    public function setInputKey(XMLSecurityKey $input_key)
    {
        $this->inputKey = $input_key;
    }


    /**
     * Get the SAML 1.1 Assertion
     * @param DOMXPath $xpath
     * @return SAML1_Assertion
     * @throws Exception
     */
    protected function parseEncryptedSAML1Assertion(DOMXpath $xpath)
    {

        if (!$this->inputKey) {
            throw new Exception('Unable to parse encrypted token without input key');
        }

        $encrypted_data = $xpath
            ->query('/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/xenc:EncryptedData');
        if (!$encrypted_data) {
            throw new Exception('EncryptedData element not found.');
        }

        if ($encrypted_data->length > 1) {
            throw new Exception('Only one encrypted element supported.');
        } elseif ($encrypted_data->length === 0) {
            throw new Exception('No encrypted element found');
        }

        $decrypted_xml = SAML2_Utils::decryptElement($encrypted_data->item(0), $this->inputKey, array());

        return new SAML1_Assertion($decrypted_xml);
    }

    /**
     * @param DOMXPath $xpath
     * @return SAML1_Assertion
     * @throws Exception
     */
    protected function parseSAML1Assertion(DOMXpath $xpath)
    {
        $assertions = $xpath->query('/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml1:Assertion');
        if ($assertions->length > 1) {
            throw new Exception('Only one assertion element supported.');
        } elseif ($assertions->length === 0) {
            throw new Exception('No assertion found element supported.');
        }

        return new SAML1_Assertion($assertions->item(0));
    }

    /**
     * @param DOMXPath $xpath
     * @return SAML2_Assertion
     * @throws Exception
     */
    protected function parseSAML2Assertion(DOMXpath $xpath)
    {
        $assertions = $xpath->query('/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion');
        if ($assertions->length > 1) {
            throw new Exception('Only one assertion element supported.');
        } elseif ($assertions->length === 0) {
            throw new Exception('No assertion found element supported.');
        }

        return new SAML2_Assertion($assertions->item(0));
    }

    /**
     * @param DOMXPath $xpath
     * @return SAML2_Assertion
     * @throws Exception
     */
    protected function parseEncryptedSAML2Assertion(DOMXpath $xpath)
    {

        if (!$this->inputKey) {
            throw new Exception('Unable to parse encrypted token without input key');
        }

        $assertions = $xpath
            ->query('/trust:RequestSecurityTokenResponseCollection/trust:RequestSecurityTokenResponse/' .
                'trust:RequestedSecurityToken/saml:EncryptedAssertion');

        if ($assertions->length > 1) {
            throw new Exception('Only one assertion element supported.');
        } elseif ($assertions->length === 0) {
            //Fallback on older WS-Trust
            $assertions = $xpath
                ->query('/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:EncryptedAssertion');
            if ($assertions->length > 1) {
                throw new Exception('Only one assertion element supported.');
            } elseif ($assertions->length === 0) {
                throw new Exception('No assertion found element supported.');
            }
        }

        $encrypted_assertion = new \SAML2_EncryptedAssertion($assertions->item(0));
        return $encrypted_assertion->getAssertion($this->inputKey);
    }
}
