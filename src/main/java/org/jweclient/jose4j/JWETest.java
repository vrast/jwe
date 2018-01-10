package org.jweclient.jose4j;

import org.apache.commons.codec.binary.Hex;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.ByteUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;

/**
 * Base class for testing different algorithms for JWE encryption.
 *
 */
class JWETest {

    protected static final Logger log = LoggerFactory.getLogger(JWETest.class);

   static void decryptTokenWithKey(String token, String key) throws Exception {
        decryptJWEToken(getKey(key), token);
    }

    static Key getKey(String keyStr) throws Exception {
        byte[] secretKey = Hex.decodeHex(keyStr.toCharArray());
        return new AesKey(secretKey);
    }

    /**
     *
     * @param key
     * @param encText
     */
     static void decryptJWEToken(Key key, String encText) {

        try {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setCompactSerialization(encText);
            jwe.setKey(key);
            String plaintext = jwe.getPlaintextString();
            log.info("Decrypted JWE: " + plaintext);

        } catch (Throwable t) {
            t.printStackTrace();
        }

    }


    /**
     * Generates random AES Key based on the number of bytes provided : 16, 24, 32 or 64.
     *
     * @param keyBytes number of bytes for key
     * @return
     */
    static Key getAESKey(int keyBytes) {
        byte[] secretKey = ByteUtil.randomBytes(keyBytes);
        log.info("Secret key:" + Hex.encodeHexString(secretKey));
        return new AesKey(secretKey);
    }

    static String getAESJWEToken(String alg, String encAlg, Key key, String payload) throws Exception {
        try {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setPayload(payload);

            // set the alg for key mgmt
            jwe.setAlgorithmHeaderValue(alg);

            // set the alg for CEK
            jwe.setEncryptionMethodHeaderParameter(encAlg);

            jwe.setKey(key);
            String serializedJwe = jwe.getCompactSerialization();
            log.info("Serialized Encrypted JWE: " + serializedJwe);
            return serializedJwe;
        } catch (Exception t) {
            t.printStackTrace();
            throw t;
        }

    }


}
