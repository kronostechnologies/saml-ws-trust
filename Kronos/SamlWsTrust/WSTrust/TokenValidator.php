<?php

namespace  Kronos\SamlWsTrust\WSTrust;

use Kronos\SamlWsTrust\SAML1\SAML1_Assertion;
use SAML2_Assertion;
use XMLSecurityKey;

class TokenValidator
{

    /**
     * @var ProviderInterface
     */
    private $provider;

    /**
     * TokenValidator constructor.
     * @param ProviderInterface $provider
     */
    public function __construct(ProviderInterface $provider)
    {

        if (!$provider->getIdpUrl()) {
            throw new \InvalidArgumentException('Invalid $idp_url');
        }

        if (!$provider->getRpRealm()) {
            throw new \InvalidArgumentException('Invalid $rp_realm');
        }

        $this->provider = $provider;
    }


    /**
     * @param Token $token
     * @return TokenValidatorResponse
     */
    public function validate(Token $token)
    {

        $assertion = $token->getAssertion();

        $response = new TokenValidatorResponse();

        $issuer = $assertion->getIssuer();
        if (!in_array($issuer, $this->provider->getTrustedIssuers())) {
            $response->addValidationError('Unexpected issuer: ' . $issuer);
        }

        $validAudiences = $assertion->getValidAudiences();
        if (is_array($validAudiences) && !in_array($this->provider->getRpRealm(), $validAudiences)) {
            $response->addValidationError('Audience does not match current realm: ' . implode(', ', $validAudiences));
        }

        $notBefore = $assertion->getNotBefore();
        $time = time();
        if ($notBefore > 0 && $time < ($notBefore - 3600)) {
            $response->addValidationError('Token not valid yet.');
        }

        $notOnOrAfter = $assertion->getNotOnOrAfter();
        if ($notOnOrAfter && $time >= $notOnOrAfter) {
            $response->addValidationError('Token expired.');
        }

        $this->validateMandatoryClaims($assertion, $response);
        $this->validateSignature($assertion, $response);

        return $response;
    }

    /**
     * @param SAML1_Assertion|SAML2_Assertion $assertion
     * @param TokenValidatorResponse $response
     */
    private function validateMandatoryClaims($assertion, TokenValidatorResponse $response)
    {
        $attributes = $assertion->getAttributes();
        foreach ($this->provider->getMandatoryClaims() as $claim) {
            if (!isset($attributes[$claim->getName()])) {
                $response->addValidationError('Claim field not found:' . $claim->getName());
                continue;
            }

            $claim_values = $attributes[$claim->getName()];
            foreach ($claim->getValues() as $mandatory_claim_value) {
                if (!in_array($mandatory_claim_value, $claim_values)) {
                    $response->addValidationError('Value not found for claim ' . $claim->getName() . ': ' . $mandatory_claim_value);
                }
            }
        }
    }

    /**
     * @param SAML1_Assertion|SAML2_Assertion $assertion
     * @param TokenValidatorResponse $response
     */
    private function validateSignature($assertion, TokenValidatorResponse $response)
    {
        $certificates = $assertion->getCertificates();
        if (empty($certificates)) {
            $response->addValidationError('No certificate found in token');
            return;
        }

        $certificate = $certificates[0];
        $fingerprint =  $this->getX509CertificateFingerprint($certificate);
        if (!in_array($fingerprint, $this->provider->getTrustedCertificates())) {
            $response->addValidationError("Certificate $fingerprint used for token signature is not trusted.");
            return;
        }

        $signKey = $this->getX509CertificatePubKey($certificate);

        try {
            $assertion->validate($signKey);
        } catch (\Exception $ex) {
            $response->addValidationError('Assertion error: ' . $ex->getMessage());
        }
    }

    /**
     * @param string $x509cert
     * @return string
     */
    private function getX509CertificateFingerprint($x509cert)
    {
        return strtolower(sha1(base64_decode($x509cert)));
    }

    /**
     * Get XMLSecurityKey for X509Certificate base64 data found in xml elements.
     * @param string $x509cert
     * @return \XMLSecurityKey
     */
    private function getX509CertificatePubKey($x509cert)
    {
        $x509cert = str_replace(array("\r", "\n"), "", $x509cert);
        $x509cert = "-----BEGIN CERTIFICATE-----\n".chunk_split($x509cert, 64, "\n")."-----END CERTIFICATE-----\n";
        $signKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'public'));
        $signKey->loadKey($x509cert, false, true);
        return $signKey;
    }
}
