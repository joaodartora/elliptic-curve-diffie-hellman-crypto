package com.joaodartora.echdcrypto.service;

import at.favre.lib.crypto.SingleStepKdf;
import com.joaodartora.echdcrypto.domain.EncryptionData;
import com.joaodartora.echdcrypto.exception.EncryptionErrorException;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.lang.ByteUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;

@Service
public class CryptoService {

    private static final Logger logger = LoggerFactory.getLogger(CryptoService.class);

    private static final String AES_ENCRYPT_ALGORITHM = "AES";
    private static final String ECC_CRYPTO_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String ELLIPTIC_CURVE_ALGORITHM = "EC";
    private static final String ELLIPTIC_CURVE_DIFFIE_HELLMAN_ALGORITHM = "ECDH";
    private static final String KDF_ALGORITHM_ID = "id-aes256-GCM";
    private static final String KDF_PARTY_U_INFO = "Apple";
    private static final String BOUNCY_CASTLE_PROVIDER_NAME = "BC";
    private static final int KDF_ALGORITHM_ID_LENGTH = 13;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public CryptoService() {
    }

    public EncryptionData encryptEcc(String message, X509Certificate certificate) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        KeyPair ephemeralKeyPair = generateKeyPair();
        ECPrivateKey ephemeralPrivateKey = (ECPrivateKey) ephemeralKeyPair.getPrivate();
        byte[] ephemeralPublicKeyBytes = getPublicKeyECPoints(ephemeralKeyPair.getPublic());
        byte[] sharedSecret = generateSharedSecret(ephemeralPrivateKey, certificate.getPublicKey());
        byte[] sharedKey = applySingleStepKDF(ephemeralPublicKeyBytes, sharedSecret);
        String cipherString = encryptMessageWithAESGCM(message, sharedKey);
        String ephemeralPublicKey = Base64.getEncoder().encodeToString(ephemeralPublicKeyBytes);
        return EncryptionData.with()
                .encryptedMessage(cipherString)
                .publicKey(ephemeralPublicKey)
                .derivedKey(sharedKey)
                .build();
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ELLIPTIC_CURVE_ALGORITHM, BOUNCY_CASTLE_PROVIDER_NAME);
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    private byte[] getPublicKeyECPoints(PublicKey publicKey) {
        ASN1Sequence sequence = DERSequence.getInstance(publicKey.getEncoded());
        DERBitString subjectPublicKey = (DERBitString) sequence.getObjectAt(1);
        return subjectPublicKey.getBytes();
    }

    private static byte[] generateSharedSecret(PrivateKey privateKey, PublicKey otherPublicKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(ELLIPTIC_CURVE_DIFFIE_HELLMAN_ALGORITHM, BOUNCY_CASTLE_PROVIDER_NAME);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(otherPublicKey, true);
        return keyAgreement.generateSecret();
    }

    private static byte[] applySingleStepKDF(byte[] ephemeralPublicKey, byte[] sharedSecret) {
        byte kdfAlgorithmIdLength = Integer.valueOf(KDF_ALGORITHM_ID_LENGTH).byteValue();
        byte[] kdfAlgorithmIdLengthBytes = new byte[1];
        kdfAlgorithmIdLengthBytes[0] = kdfAlgorithmIdLength;
        byte[] kdfAlgorithmId = KDF_ALGORITHM_ID.getBytes(StandardCharsets.UTF_8);
        byte[] kdfPartyUInfo = KDF_PARTY_U_INFO.getBytes(StandardCharsets.UTF_8);
        byte[] otherInfo = ByteUtil.concat(kdfAlgorithmIdLengthBytes, kdfAlgorithmId, kdfPartyUInfo, ephemeralPublicKey);
        return SingleStepKdf.fromSha256().derive(sharedSecret, 32, otherInfo);
    }

    public String encryptMessageWithAESGCM(String message, byte[] derivedKey) {
        try {
            SecretKey secretKey = new SecretKeySpec(derivedKey, AES_ENCRYPT_ALGORITHM);
            Cipher cipher = Cipher.getInstance(ECC_CRYPTO_TRANSFORMATION, BOUNCY_CASTLE_PROVIDER_NAME);

            byte[] iv = new byte[12];
            IvParameterSpec ivParams = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);

            byte[] encryptMeBytes = message.getBytes();
            byte[] cipherText = cipher.doFinal(encryptMeBytes);
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            logger.error("Error encrypting message.", e);
            throw new EncryptionErrorException(e);
        }
    }
}


