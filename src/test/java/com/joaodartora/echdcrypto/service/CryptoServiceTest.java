package com.joaodartora.echdcrypto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joaodartora.echdcrypto.domain.EncryptionData;
import com.joaodartora.echdcrypto.domain.PaymentData;
import com.joaodartora.echdcrypto.stub.X509CertificateStub;
import com.joaodartora.echdcrypto.utils.EncryptionUtils;
import org.bouncycastle.util.encoders.Hex;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoServiceTest {

    private final CryptoService cryptoService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public CryptoServiceTest() {
        this.cryptoService = new CryptoService();
    }

    @Test
    public void encryptEccWithSuccessShouldEncryptAndDecryptMessageWithEccCrypto() throws JoseException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        X509Certificate x509Certificate = X509CertificateStub.buildLeafCertificate();
        String message = objectMapper.writeValueAsString(buildPassData());

        EncryptionData encryptionData = cryptoService.encryptEcc(message, x509Certificate);

        byte[] decryptedData = EncryptionUtils.decryptEcc(encryptionData);
        String decryptedString = new String(decryptedData);
        PaymentData decryptedPaymentData = objectMapper.readValue(decryptedString, PaymentData.class);

        byte[] decode = Base64.getDecoder().decode(encryptionData.getPublicKey());
        assertAll(
                () -> assertEquals("11223344", decryptedPaymentData.getAccountNumber()),
                () -> assertEquals("DEFAULT_PRODUCT", decryptedPaymentData.getProductType()),
                () -> assertEquals("ANTONIETA NIEVES", decryptedPaymentData.getName()),
                () -> assertEquals("65as4f65sa4f56sa4f65f654sa", decryptedPaymentData.getNonce()),
                () -> assertEquals("as4f65as4g65a4g65sd4g65sd4g65s4dh5fdh98fd4n654d35b654", decryptedPaymentData.getNonceSignature()),
                () -> assertEquals("1", decryptedPaymentData.getVersion()),
                () -> assertTrue(encryptionData.getPublicKey().endsWith("=")),
                () -> assertTrue(Hex.toHexString(decode).startsWith("04"))
        );
    }

    private PaymentData buildPassData() {
        return PaymentData.with()
                .accountNumber("11223344")
                .productType("DEFAULT_PRODUCT")
                .name("ANTONIETA NIEVES")
                .nonce("65as4f65sa4f56sa4f65f654sa")
                .nonceSignature("as4f65as4g65a4g65sd4g65sd4g65s4dh5fdh98fd4n654d35b654")
                .version("1")
                .build();
    }
}
