# SAML WS-Trust
Improvement of simplesamlphp WS-Trust implementation for SAML 1.1 and SAML 2.0

## Setup

```
$logger; // Psr\LoggerInterface
$container = new Kronos\SamlWsTrust\SAML\Container($logger);
SAML2\Compat\ContainerSingleton::setContainer($container);
```
