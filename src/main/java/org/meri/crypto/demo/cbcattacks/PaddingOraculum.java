package org.meri.crypto.demo.cbcattacks;

import org.apache.shiro.ShiroException;
import org.apache.shiro.crypto.CryptoException;
import org.apache.shiro.crypto.DefaultBlockCipherService;
import org.meri.crypto.demo.util.StringCipher;

public class PaddingOraculum {
  
  private final StringCipher cipher;
  private byte[] key;

  public PaddingOraculum(DefaultBlockCipherService cipher) {
    super();
    this.cipher = new StringCipher(cipher);
    key = cipher.generateNewKey().getEncoded();
  }
  
  public byte[] encrypt(String message) throws CryptoException {
    return cipher.encrypt(message, key);
  }

  public boolean verifyPadding(byte[] ciphertext) {
    try {
      cipher.decrypt(ciphertext, key);
      return true;
    } catch (ShiroException ex) {
      return false;
    }
  }

  public int getBlockSize() {
    return cipher.getBlockSize();
  }
}