package org.jweclient.jose4j;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;


/**
 * This class is going to perform JWE encryption with AES in GCM mode.
 *
 * @author vikas
 * 
 */
public class JWEGCMTest extends JWETest {

    protected static final Logger log = LoggerFactory.getLogger(JWEGCMTest.class);


    public static void main(String[] args) {
        try {

            /*
            *   Here we are trying to test multiple combinations for "key-management algorithm" and
            *   "content-encryption algorithm" for GCM
            *
            * */
            String payload = "Hello World, testing the JWE implementation!";

            testJWE_DIR_GCM(payload);

            testJWE_GCM_GCM_128(payload);

            testJWE_GCM_GCM_256(payload);

            testDecryptionWithProvidedKey();

            testEncryptionWithProvidedKey(payload);


        } catch (Throwable t) {
            t.printStackTrace();
        }

    }

    private static void testDecryptionWithProvidedKey() throws Exception {
        String token = "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJRbWwtbjN0MzJfSmhKVDU3IiwidGFnIjoiUFI2SlRQYUxXVnZabjl4Yk56cERiZyJ9.uZv2vvHlGcKF3G8ZW3V_Lg.AOEvlFWsG0Kh-0_N.m_J3RajlkCIhxM40XJFzANwV8w5MRgORThYmrQvvi3iSZg.9Ke5_8Lnvbq5Cw7yA0fZgw";
        String key = "009c1934ee05fd0c655d2604bfe94fd0";
        decryptTokenWithKey(token, key);
    }

    private static void testEncryptionWithProvidedKey(String payload) throws Exception {
        String keyStr = "009c1934ee05fd0c655d2604bfe94fd0";
        Key key = getKey(keyStr);
        String jweToken = getAESJWEToken(KeyManagementAlgorithmIdentifiers.A256GCMKW,
                ContentEncryptionAlgorithmIdentifiers.AES_256_GCM, key, payload);
        decryptJWEToken(key, jweToken);
    }


    /**
     * * Uses A128GCMKW for key encryption and AES_128 for content encryption
     *
     * @param payload
     * @throws Exception
     */
    private static void testJWE_GCM_GCM_128(String payload) throws Exception {
        int keyBytes = 16;
        Key key = getAESKey(keyBytes);

        String jweToken = getAESJWEToken(KeyManagementAlgorithmIdentifiers.A128GCMKW,
                ContentEncryptionAlgorithmIdentifiers.AES_128_GCM, key, payload);
        decryptJWEToken(key, jweToken);
    }

    /**
     * Uses A256GCMKW for key encryption and AES_256 for content encryption
     *
     * @param payload
     * @throws Exception
     */
    private static void testJWE_GCM_GCM_256(String payload) throws Exception {
        int keyBytes = 32;
        Key key = getAESKey(keyBytes);
        String jweToken = getAESJWEToken(KeyManagementAlgorithmIdentifiers.A256GCMKW,
                ContentEncryptionAlgorithmIdentifiers.AES_256_GCM, key, payload);
        decryptJWEToken(key, jweToken);
    }

    /**
     *  Uses AES_256 for content encryption. The key wrapping step is skipped here and the second part of
     *  output encrypted token will be an empty string.
     *
     * @param payload
     * @throws Exception
     */
    private static void testJWE_DIR_GCM(String payload) throws Exception {

        int keyBytes = 32;
        Key key = getAESKey(keyBytes);
        // requires JDK 1.8
        String jweToken = getAESJWEToken(KeyManagementAlgorithmIdentifiers.DIRECT,
                ContentEncryptionAlgorithmIdentifiers.AES_256_GCM, key, payload);
        decryptJWEToken(key, jweToken);
    }


}
