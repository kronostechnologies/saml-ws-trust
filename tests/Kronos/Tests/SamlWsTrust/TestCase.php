<?php


namespace Kronos\Tests\SamlWsTrust;


use Psr\Log\LoggerInterface;

class TestCase extends \PHPUnit_Framework_TestCase
{
    protected $logger;

    public function setUp()
    {
        parent::setUp();
        $this->logger = $this->getMockWithoutInvokingTheOriginalConstructor(LoggerInterface::class);
        $container = new \Kronos\SamlWsTrust\SAML2\Container($this->logger);
        \SAML2\Compat\ContainerSingleton::setContainer($container);
    }
}
