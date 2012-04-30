package org.meri.crypto.demo.cbcattacks;

import static org.junit.Assert.assertEquals;

import java.security.Security;
import java.util.Arrays;

import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.BlowfishCipherService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.meri.crypto.demo.cbcattacks.PaddingOraculum;
import org.meri.crypto.demo.util.StringCipher;

public class AttacksDemo {

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
  public void testModifiedMessage_AES() {
    String email = "Hi,\n" + "send Martin all requested money please.\n\n" + "With Regards, \n" + "Accounting\n";
    // plumbing: create cipher and the secret key
    StringCipher cipher = new StringCipher(new AesCipherService());
    byte[] key = cipher.generateNewKey();
    // encrypt the message
    byte[] ciphertext = cipher.encrypt(email, key);
    ;
    // attack: modify the encrypted message
    String myMessage = "Hi,\n" + "give Andrea all requested money please.\n\n" + "With Regards, \n" + "Accounting\n";

    for (int i = 0; i < 16; i++) {
      ciphertext[i] = (byte) (ciphertext[i] ^ myMessage.getBytes()[i] ^ email.getBytes()[i]);
    }
    // decrypt and verify
    String result = cipher.decrypt(ciphertext, key);
    assertEquals(myMessage, result);
  }

  @Test
  public void testModifiedMessage_Blowfish() {
    String email = "Pay 100 dollars to them, but nothing more. Accounting\n";

    StringCipher cipher = new StringCipher(new BlowfishCipherService());
    byte[] key = cipher.generateNewKey();
    byte[] ciphertext = cipher.encrypt(email, key);

    String myMessage = "Pay 900 dollars to them, but nothing more. Accounting\n";

    for (int i = 0; i < 8; i++) {
      ciphertext[i] = (byte) (ciphertext[i] ^ myMessage.getBytes()[i] ^ email.getBytes()[i]);
    }
    String result = cipher.decrypt(ciphertext, key);
    assertEquals(myMessage, result);
  }

  @Test
  public void testPaddingOracle_Blowfish() {
    String message = "secret message!";

    PaddingOraculum oraculum = new PaddingOraculum(
        new BlowfishCipherService());
    // Obtain a ciphertext from the oraculum. Only oraculum knows the secret
    // key.
    byte[] ciphertext = oraculum.encrypt(message);
    // use oraculum to decrypt the message
    String result = decryptLastBlock(oraculum, ciphertext);

    // the original message had padding 1
    assertEquals("essage!" + (char) 1, result);
  }

  @Test
  public void testPaddingOracle_AES() {
    String message = "secret message!";

    PaddingOraculum oraculum = new PaddingOraculum(new AesCipherService());
    // Obtain a ciphertext from the oraculum. Only oraculum knows the secret
    // key.
    byte[] ciphertext = oraculum.encrypt(message);
    // use oraculum to decrypt the message
    String result = decryptLastBlock(oraculum, ciphertext);

    // the original message had padding 1
    assertEquals("secret message!" + (char) 1, result);
  }

private String decryptLastBlock(PaddingOraculum oraculum, byte[] ciphertext) {
  byte[] ivAndBlock = getLastTwoBlocks(ciphertext, 
      oraculum.getBlockSize());
  byte[] ivMod = new byte[oraculum.getBlockSize()];
  Arrays.fill(ivMod, (byte) 0);

  for (int i = oraculum.getBlockSize() - 1; i >= 0; i--) {
    int expectedPadding = oraculum.getBlockSize() - i;
    // add padding to the initial vector
    xorPad(ivMod, expectedPadding);

    // loop through possible values of ivModification[i]
    for (ivMod[i] = Byte.MIN_VALUE; ivMod[i] < Byte.MAX_VALUE; ivMod[i]++) {
      byte[] modifiedCiphertext = replaceBeginning(ivAndBlock, ivMod);

      if (oraculum.verifyPadding(modifiedCiphertext)) {
        // we can stop looping
        // the ivModification[i] = solution ^ expectedPadding ^ ivAndBlock[i]
        break;
      }
    }

    // remove the padding from the initial vector
    xorPad(ivMod, expectedPadding);
  }

  // initial vector now contains the solution xor original initial vector
  String result = "";
  for (int i = 0; i < ivMod.length; i++) {
    ivMod[i] = (byte) (ivMod[i] ^ ivAndBlock[i]);
    result += (char) ivMod[i];
  }
  return result;
}

  private void xorPad(byte[] ivModification, int expectedPadding) {
    for (int j = ivModification.length - 1; j > ivModification.length - expectedPadding - 1; j--) {
      ivModification[j] = (byte) (ivModification[j] ^ expectedPadding);
    }
  }

  private byte[] getLastTwoBlocks(byte[] ciphertext, int blockLength) {
    byte[] result = new byte[blockLength * 2];
    System.arraycopy(ciphertext, ciphertext.length - blockLength * 2, result, 0, blockLength * 2);
    return result;
  }

  private byte[] replaceBeginning(byte[] ciphertext, byte[] modifiedInitialVector) {
    byte[] modifiedCiphertext = Arrays.copyOf(ciphertext, ciphertext.length);
    System.arraycopy(modifiedInitialVector, 0, modifiedCiphertext, 0, modifiedInitialVector.length);
    return modifiedCiphertext;
  }

}