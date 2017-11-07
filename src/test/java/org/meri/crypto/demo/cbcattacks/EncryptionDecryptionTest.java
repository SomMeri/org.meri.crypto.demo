package org.meri.crypto.demo.cbcattacks;

import static org.junit.Assert.assertEquals;

import java.security.Key;

import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.BlowfishCipherService;
import org.apache.shiro.crypto.CipherService;
import org.apache.shiro.crypto.DefaultBlockCipherService;
import org.apache.shiro.util.ByteSource;
import org.junit.Test;
import org.meri.crypto.demo.util.StringCipher;

public class EncryptionDecryptionTest {

  @Test
  public void encryptStringMessage_AES() {
    String secret = "Tell nobody!";
    StringCipher cipher = new StringCipher(new BlowfishCipherService());

    byte[] key = cipher.generateNewKey();
    byte[] ciphertext = cipher.encrypt(secret, key);
    String secret2 = cipher.decrypt(ciphertext, key);

    // verify correctness
    assertEquals(secret, secret2);
  }

  @Test
  public void encryptStringMessage_Blowfish() {
    String secret = "Tell nobody!";
    DefaultBlockCipherService cipher = new AesCipherService();

    byte[] key = generateNewKey(cipher);
    byte[] ciphertext = encryptTheSecret(cipher, secret, key);
    String secret2 = decryptTheMessage(cipher, ciphertext, key);

    // verify correctness
    assertEquals(secret, secret2);
  }

  private String decryptTheMessage(CipherService cipher, byte[] ciphertext, byte[] key) {
    //decrypt the data
    ByteSource decrypted = cipher.decrypt(ciphertext, key);
    //convert byte array back to string and return
    String result = CodecSupport.toString(decrypted.getBytes());
    return result;
  }

  private byte[] encryptTheSecret(CipherService cipher, String secret, byte[] key) {
    //convert data into byte array
    byte[] secretBytes = CodecSupport.toBytes(secret);
    //encrypt data 
    ByteSource ciphertext = cipher.encrypt(secretBytes, key);
    //return byte array containing encrypted data
    return ciphertext.getBytes();
  }

  private byte[] generateNewKey(DefaultBlockCipherService cipher) {
    Key key = cipher.generateNewKey();
    byte[] keyBytes = key.getEncoded();
    return keyBytes;
  }
}
