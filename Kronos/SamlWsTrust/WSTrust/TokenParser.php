<?php

namespace Kronos\SamlWsTrust\WSTrust;

use DOMDocument;
use DOMElement;
use DOMXPath;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Utils;
use SAML2\Assertion;

class TokenParser
{
    private string $tokenType;
    private ?XMLSecurityKey $inputKey = null;

    public function __construct(string $token_type)
    {
        if (!Token::isTokenType($token_type)) {
            throw new \InvalidArgumentException('Invalid $token_type');
        }

        $this->tokenType = $token_type;
    }

    /**
     * @param non-empty-string $token_xml
     * @throws Exception
     */
    public function parseToken(string $token_xml): Token
    {
        $dom = new DOMDocument();
        $token_xml = str_replace(array('\"', "\r"), array('"', ""), $token_xml);
        if (!$token_xml) {
            throw new \InvalidArgumentException("Expected non-empty xml");
        }
        $dom->loadXML($token_xml);

        $xpath = new \DOMXpath($dom);
        $xpath->registerNamespace('wst', 'http://schemas.xmlsoap.org/ws/2005/02/trust');
        $xpath->registerNamespace('trust', 'http://docs.oasis-open.org/ws-sx/ws-trust/200512');
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
        $xpath->registerNamespace('saml1', 'urn:oasis:names:tc:SAML:1.0:assertion');

        switch ($this->tokenType) {
            case 'SAML_2_0':
                return $this->parseSAML2Assertion($xpath);
            case 'SAML_2_0_ENC':
                return $this->parseEncryptedSAML2Assertion($xpath);
            default:
                throw new  \DomainException('Invalid token type: ' . $this->tokenType);
        }
    }

    public function setInputKey(XMLSecurityKey $input_key)
    {
        $this->inputKey = $input_key;
    }

    /**
     * @param DOMXPath $xpath
     * @throws Exception
     */
    protected function parseSAML2Assertion(DOMXpath $xpath): Token
    {
        try {
            $assertions = $xpath->query('/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion');
            if ($assertions->length > 1) {
                throw new Exception('Only one assertion element supported.');
            }

            if ($assertions->length === 0) {
                throw new Exception('No assertion found element supported.');
            }

            /** @var DOMElement $assertionElement we check thelength above */
            $assertionElement = $assertions->item(0);
            $deflateEncodedAssertion = $this->deflateEncodeInitialAssertion($assertionElement);
            $assertion = new Assertion($assertionElement);
            return new Token($this->tokenType, $assertion, $deflateEncodedAssertion);
        } catch (\Exception $ex) {
            throw new Exception($ex->getMessage(), 0, $ex);
        }
    }

    /**
     * @param DOMXPath $xpath
     * @throws Exception
     */
    protected function parseEncryptedSAML2Assertion(DOMXpath $xpath): Token
    {
        try {
            if (!$this->inputKey) {
                throw new Exception('Unable to parse encrypted token without input key');
            }

            $assertions = $xpath
                ->query('/trust:RequestSecurityTokenResponseCollection/trust:RequestSecurityTokenResponse/' .
                    'trust:RequestedSecurityToken/saml:EncryptedAssertion');

            if ($assertions->length > 1) {
                throw new Exception('Only one assertion element supported.');
            }

            if ($assertions->length === 0) {
                //Fallback on older WS-Trust
                $assertions = $xpath
                    ->query('/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:EncryptedAssertion');
                if ($assertions->length > 1) {
                    throw new Exception('Only one assertion element supported.');
                }

                if ($assertions->length === 0) {
                    throw new Exception('No assertion found element supported.');
                }
            }

            /** @var DOMElement $assertion we check the lenght above */
            $assertion = $assertions->item(0);
            $encryptedAssertionElement = $this->getEncryptedDataElement($assertion);
            $decryptedAssertionElement = Utils::decryptElement($encryptedAssertionElement, $this->inputKey);
            $deflateEncodedAssertion = $this->deflateEncodeInitialAssertion($decryptedAssertionElement);

            $assertion = new Assertion($decryptedAssertionElement);
            return new Token($this->tokenType, $assertion, $deflateEncodedAssertion);
        } catch (\Exception $ex) {
            throw new Exception($ex->getMessage(), 0, $ex);
        }
    }

    /**
     * @param DOMElement $xml
     * @return DOMElement
     * @throws Exception
     */
    protected function getEncryptedDataElement(DOMElement $xml)
    {
        $data = Utils::xpQuery($xml, './xenc:EncryptedData');
        if (count($data) === 0) {
            throw new Exception('Missing encrypted data in <saml:EncryptedAssertion>.');
        }

        if (count($data) > 1) {
            throw new Exception('More than one encrypted data element in <saml:EncryptedAssertion>.');
        }
        $element = $data[0];
        if (!$element instanceof DOMElement) {
            throw new \RuntimeException("Expected DOMElement in EncryptedData");
        }
        return $element;
    }

    protected function deflateEncodeInitialAssertion(DOMElement $xml): string
    {
        $document = $xml->ownerDocument;
        if (!$document instanceof DOMDocument) {
            throw new \RuntimeException("Could not find assertion dom document");
        }
        $xmlString = $document->saveXML($xml);
        return base64_encode(gzdeflate($xmlString));
    }
}
