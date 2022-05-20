<?php

namespace Kronos\SamlWsTrust\SAML2;

use DOMNode;
use Psr\Log\LoggerInterface;
use SAML2\Compat\AbstractContainer;

class Container extends AbstractContainer
{
    private LoggerInterface $logger;

    /**
     * @var string
     */
    private $redirectUrl;

    /**
     * @var array
     */
    private $redirectData;

    /**
     * @var string
     */
    private $postRedirectUrl;

    /**
     * @var array
     */
    private $postRedirectData;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    public function getLogger(): LoggerInterface
    {
        return $this->logger;
    }

    /**
     * Generate a random identifier for identifying SAML2 documents.
     */
    public function generateId(){
        return Random::generateID();
    }

    /**
     * Log an incoming message to the debug log.
     *
     * Type can be either:
     * - **in** XML received from third party
     * - **out** XML that will be sent to third party
     * - **encrypt** XML that is about to be encrypted
     * - **decrypt** XML that was just decrypted
     *
     * @param string|DOMNode $message
     * @param string $type
     * @return void
     */
    public function debugMessage($message, $type){
        if($message instanceof DOMNode) {
            $message = "DOMNode: " . $message->textContent;
        }
        $this->logger->debug($message, ['type' => $type]);
    }

    /**
     * Trigger the user to perform a GET to the given URL with the given data.
     *
     * @param string $url
     * @param array $data
     * @return void
     */
    public function redirect($url, $data = array())
    {
        $this->redirectUrl = $url;
        $this->redirectData = $data;
    }

    /**
     * Trigger the user to perform a POST to the given URL with the given data.
     *
     * @param string $url
     * @param array $data
     * @return void
     */
    public function postRedirect($url, $data = array())
    {
        $this->postRedirectUrl = $url;
        $this->postRedirectData = $data;
    }

    /**
     * @return string
     */
    public function getRedirectUrl()
    {
        return $this->redirectUrl;
    }

    /**
     * @return array
     */
    public function getRedirectData()
    {
        return $this->redirectData;
    }

    /**
     * @return string
     */
    public function getPostRedirectUrl()
    {
        return $this->postRedirectUrl;
    }

    /**
     * @return array
     */
    public function getPostRedirectData()
    {
        return $this->postRedirectData;
    }
}
