package org.meri.crypto.demo.util;

import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.CryptoException;
import org.apache.shiro.crypto.DefaultBlockCipherService;

public class StringCipher {
  
  private final DefaultBlockCipherService cipher;

  public StringCipher(DefaultBlockCipherService cipher) {
    super();
    this.cipher = cipher;
  }
  
  public byte[] generateNewKey() {
    return cipher.generateNewKey().getEncoded();
  }

  public String decrypt(byte[] encrypted, byte[] key) throws CryptoException {
    return CodecSupport.toString(cipher.decrypt(encrypted, key).getBytes());
  }

  public byte[] encrypt(String message, byte[] key) throws CryptoException {
    return cipher.encrypt(CodecSupport.toBytes(message), key).getBytes();
  }

  public int getBlockSize() {
    int blockSize = cipher.getBlockSize();
    if (blockSize==0) {
      //0 stands for "the default value", so I'm going 
      //to do ugly hack
      if (cipher.getAlgorithmName().equals("AES"))
        return 16;
      if (cipher.getAlgorithmName().equals("Blowfish"))
        return 8;
    }
    
    return blockSize;
  }
}
