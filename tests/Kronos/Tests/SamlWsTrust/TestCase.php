<?php


namespace Kronos\Tests\SamlWsTrust;


use Psr\Log\LoggerInterface;

class TestCase extends \PHPUnit\Framework\TestCase
{
    protected $logger;

    public function setUp(): void
    {
        parent::setUp();
        $this->logger = $this->createMock(LoggerInterface::class);
        $container = new \Kronos\SamlWsTrust\SAML2\Container($this->logger);
        \SAML2\Compat\ContainerSingleton::setContainer($container);
    }
}
