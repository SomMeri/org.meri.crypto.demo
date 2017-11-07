package org.meri.crypto.demo.cbcattacks;

import static org.junit.Assert.fail;

import java.security.Security;

import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.DefaultBlockCipherService;
import org.apache.shiro.crypto.OperationMode;
import org.apache.shiro.crypto.PaddingScheme;
import org.apache.shiro.util.ByteSource;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

public class ShiroBouncyIntegrationTest {

  @BeforeClass
  public static void setUp() {
    installBouncyCastle();
  }

  private static BouncyCastleProvider installBouncyCastle() {
    BouncyCastleProvider provider = new BouncyCastleProvider();
    Security.addProvider(provider);
    return provider;
  }

  @Test
  public void testAuthentication() {
    String message = "secret message";

    AesCipherService aesCipher = new AesCipherService();
    assertNoIngetrityCheck(message, aesCipher);

    GCMCipherService gcmCipher = new GCMCipherService();
    assertIngetrityCheck(message, gcmCipher);

    EAXCipherService eaxCipher = new EAXCipherService();
    assertIngetrityCheck(message, eaxCipher);

    // //WARNING: does not work!!!
    // CCMCipherService ccmCipher = new CCMCipherService();
    // assertIngetrityCheckDecrypt(message, ccmCipher);
  }

  @Test
  public void testGCMAuthentication() {
    String message = "secret message";

    GCMCipherService gcmCipher = new GCMCipherService();
    assertIngetrityCheck(message, gcmCipher);
  }

  private void assertNoIngetrityCheck(String message, DefaultBlockCipherService cipher) {
    byte[] key = cipher.generateNewKey().getEncoded();
    byte[] messageBytes = CodecSupport.toBytes(message);
    ByteSource encrypt = cipher.encrypt(messageBytes, key);

    // change ciphertext
    encrypt.getBytes()[3] = 0;
    // it is possible to decrypt ciphertext with changed initial vector
    cipher.decrypt(encrypt.getBytes(), key);
  }

  private void assertIngetrityCheck(String message, DefaultBlockCipherService cipher) {
    byte[] key = cipher.generateNewKey().getEncoded();
    byte[] messageBytes = CodecSupport.toBytes(message);
    ByteSource encrypt = cipher.encrypt(messageBytes, key);

    // change the ciphertext
    encrypt.getBytes()[3] = 0;

    try {
      // it should not be possible to decrypt changed ciphertext
      cipher.decrypt(encrypt.getBytes(), key).getBytes();
    } catch (Exception ex) {
      return;
    }
    fail("It should not be possible to decrypt changed ciphertext.");
  }
}

class GCMCipherService extends DefaultBlockCipherService {

  private static final String ALGORITHM_NAME = "AES";

  public GCMCipherService() {
    super(ALGORITHM_NAME);
    setMode(OperationMode.GCM);
    setPaddingScheme(PaddingScheme.NONE);
  }

}

class EAXCipherService extends DefaultBlockCipherService {

  private static final String ALGORITHM_NAME = "AES";

  public EAXCipherService() {
    super(ALGORITHM_NAME);
    setMode(OperationMode.EAX);
    setPaddingScheme(PaddingScheme.NONE);
  }

}

// WARNING: does not work!!!
class CCMCipherService extends DefaultBlockCipherService {

  private static final String ALGORITHM_NAME = "AES";

  public CCMCipherService() {
    super(ALGORITHM_NAME);
    setMode(OperationMode.CCM);
    setPaddingScheme(PaddingScheme.NONE);
  }

}
