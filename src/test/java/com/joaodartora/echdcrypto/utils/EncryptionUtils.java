package com.joaodartora.echdcrypto.utils;

import com.joaodartora.echdcrypto.domain.EncryptionData;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

public class EncryptionUtils {

    public static byte[] decryptEcc(EncryptionData encryptionData) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        byte[] iv = new byte[12];
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        SecretKey secretKey = new SecretKeySpec(encryptionData.getDerivedKey(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);

        String decryptMe = encryptionData.getEncryptedMessage();
        byte[] decryptMeBytes = Base64.getDecoder().decode(decryptMe);
        return cipher.doFinal(decryptMeBytes);
    }
}
