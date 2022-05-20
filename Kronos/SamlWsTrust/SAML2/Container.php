<?php

namespace Kronos\SamlWsTrust\SAML2;

use DOMElement;
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

    private string $tmpDir;

    public function __construct(
        LoggerInterface $logger,
        string $tmpDir = '/tmp/'
    ) {
        $this->logger = $logger;
        $this->tmpDir = $tmpDir;
    }

    public function getLogger(): LoggerInterface
    {
        return $this->logger;
    }

    /**
     * Generate a random identifier for identifying SAML2 documents.
     */
    public function generateId(): string
    {
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
     * @param string|DOMElement $message
     * @param string $type
     * @return void
     */
    public function debugMessage($message, string $type): void
    {
        if ($message instanceof DOMElement) {
            $message = "DOMElement: " . $message->textContent;
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
    public function redirect(string $url, array $data = array()): void
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
    public function postRedirect(string $url, array $data = array()): void
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

    /**
     * This function retrieves the path to a directory where temporary files can be saved.
     *
     * @return string Path to a temporary directory, without a trailing directory separator.
     * @throws \Exception If the temporary directory cannot be created or it exists and does not belong
     * to the current user.
     */
    public function getTempDir(): string
    {
        return $this->tmpDir;
    }

    /**
     * Atomically write a file.
     *
     * This is a helper function for writing data atomically to a file. It does this by writing the file data to a
     * temporary file, then renaming it to the required file name.
     *
     * @param string $filename The path to the file we want to write to.
     * @param string $data The data we should write to the file.
     * @param int $mode The permissions to apply to the file. Defaults to 0600.
     * @return void
     */
    public function writeFile(string $filename, string $data, int $mode = null): void
    {
        file_put_contents($filename, $data);
        if ($mode !== null) {
            chmod($filename, $mode);
        }
    }
}
