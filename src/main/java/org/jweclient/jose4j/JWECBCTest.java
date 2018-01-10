package org.jweclient.jose4j;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;

/**
 * This class is going to perform JWE encryption using AES in CBS mode.
 *
 * @author vikas
 * 
 */
public class JWECBCTest extends JWETest {

    protected static final Logger log = LoggerFactory.getLogger(JWECBCTest.class);

    public static void main(String[] args) {
        try {

            /**
            *   Here we are trying to test multiple combinations for "key-management algorithm" and
            *   "content-encryption algorithm" in CBS mode
            *
            * */
            String payload = "Hello World, testing the JWE implementation!";

            testJWE_CBC_HMAC_256(payload);

            testJWE_CBC_HMAC_128(payload);

            testJWE_DIR_CBC_HMAC_128(payload);

            testJWE_DIR_CBC_HMAC_256(payload);

            testDecryptionWithProvidedKey();

            testEncryptionWithProvidedKey(payload);

        } catch (Throwable t) {
            t.printStackTrace();
        }

    }

    private static void testDecryptionWithProvidedKey() throws Exception {
        String token = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.3rpGDfKNJsnxjuOVd10Rnj2WzMbKCP994u7gQyhSKC2brvno8KkGr5_JAQUIo3HMatZPv5uctCjmP3btXe9T7_TkljygH9r1.V7vERLwrq_-C0APNedo7yg.cvyOBtLIes0k4BloUYQnwSEVnwoHBOHx_r9iK9XnmdV7UP4yMKvlff-5EL-Qvw2E.rE4iRKYNUpLjq4NhN0GVn1inZSB5ogVhFHZovD8obBk";
        String key = "98455b33b64f33d42f6709cb33d8f4c6a0145a7539a89fa6597511c1caab75db";
        decryptTokenWithKey(token, key);
    }

    private static void testEncryptionWithProvidedKey(String payload) throws Exception {
        String keyStr = "98455b33b64f33d42f6709cb33d8f4c6a0145a7539a89fa6597511c1caab75db";
        Key key = getKey(keyStr);
        String jweToken = getAESJWEToken(KeyManagementAlgorithmIdentifiers.A256KW,
                ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512, key, payload);
        decryptJWEToken(key, jweToken);
    }

    /**
     * Uses A256KW for key encryption and AES_256 for content encryption & SHA512 for
     * HMAC generation on encrypted content.
     *
     * @param payload
     * @throws Exception
     */
    private static void testJWE_CBC_HMAC_256(String payload) throws Exception {
        int keyBytes = 32;
        Key key = getAESKey(keyBytes);

        String jweToken = getAESJWEToken(KeyManagementAlgorithmIdentifiers.A256KW,
                ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512, key, payload);
        decryptJWEToken(key, jweToken);
    }

    /**
     * Uses A128KW for key encryption and AES_128 for content encryption & SHA-256 for
     * HMAC generation on encrypted content.
     *
     * @param payload
     * @throws Exception
     */
    private static void testJWE_CBC_HMAC_128(String payload) throws Exception {
        int keyBytes = 16;
        Key key = getAESKey(keyBytes);
        String jweToken = getAESJWEToken(KeyManagementAlgorithmIdentifiers.A128KW,
                ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256, key, payload);
        decryptJWEToken(key, jweToken);
    }

    /**
     *  Uses AES_128 for content encryption. The key wrapping step is skipped here and the second part of
     *  output encrypted token will be an empty string.
     *
     * @param payload
     * @throws Exception
     */
    private static void testJWE_DIR_CBC_HMAC_128(String payload) throws Exception {

        int keyBytes = 32;
        Key key = getAESKey(keyBytes);
        String jweToken = getAESJWEToken(KeyManagementAlgorithmIdentifiers.DIRECT,
                ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256, key, payload);
        decryptJWEToken(key, jweToken);
    }

    private static void testJWE_DIR_CBC_HMAC_256(String payload) throws Exception {

        int keyBytes = 64;
        Key key = getAESKey(keyBytes);
        // requires JDK 1.8
        String jweToken = getAESJWEToken(KeyManagementAlgorithmIdentifiers.DIRECT,
                ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512, key, payload);
        decryptJWEToken(key, jweToken);
    }

}
