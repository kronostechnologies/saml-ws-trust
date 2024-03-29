<?php

namespace Kronos\SamlWsTrust\SAML2;

/**
 * Utility class for random data generation and manipulation.
 *
 * @package SimpleSAMLphp
 */
class Random
{

    /**
     * The fixed length of random identifiers.
     */
    const ID_LENGTH = 43;

    /**
     * Generate a random identifier, ID_LENGTH bytes long.
     *
     * @return string A ID_LENGTH-bytes long string with a random, hex-encoded string.
     *
     * @author Andreas Solberg, UNINETT AS <andreas.solberg@uninett.no>
     * @author Olav Morken, UNINETT AS <olav.morken@uninett.no>
     * @author Jaime Perez, UNINETT AS <jaime.perez@uninett.no>
     */
    public static function generateID(): string
    {
        /** @psalm-suppress RedundantCast */
        $length = (int)((self::ID_LENGTH - 1)/2);
        return '_'.bin2hex(openssl_random_pseudo_bytes($length));
    }
}
