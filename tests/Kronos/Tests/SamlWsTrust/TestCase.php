<?php


namespace Kronos\Tests\SamlWsTrust;


use Kronos\SamlWsTrust\SAML2\Container;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use SAML2\Compat\ContainerSingleton;

class TestCase extends \PHPUnit\Framework\TestCase
{
    /**
     * @var MockObject&LoggerInterface
     */
    protected $logger;

    public function setUp(): void
    {
        parent::setUp();
        $this->logger = $this->createMock(LoggerInterface::class);
        $container = new Container($this->logger);
        ContainerSingleton::setContainer($container);
    }
}
