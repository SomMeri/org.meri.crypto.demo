package org.meri.crypto.demo.util;

import org.apache.shiro.util.ByteSource;

public class PrintArrayUtil {
//FIXME remove dependency on shiro!
  public String toString(ByteSource ciphertext) {
    return toString(ciphertext.getBytes());
  }

  public String toString(byte[] bytes) {
    String result = "{";
    for (int i = 0; i < bytes.length-1; i++) {
      result += bytes[i] + ",";
    }
    result += bytes[bytes.length-1] + "}";

    return result;
  }

  public String toBinaryString(byte[] bytes) {
    String result = "";
    for (int i = 0; i < bytes.length; i++) {
      result += toBinaryString(bytes[i]);
    }

    return result;
  }

  public String toBinaryString(byte number) {
    String result = "";
    int i = 256; // max number * 2
    while ((i >>= 1) > 0) {
      result += (((number & i) != 0 ? "1" : "0"));
    }

    return result;
  }


}
