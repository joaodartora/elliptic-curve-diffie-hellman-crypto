package com.joaodartora.echdcrypto.domain;

public class EncryptionData {

    private String encryptedMessage;
    private String publicKey;
    private byte[] derivedKey;

    public String getEncryptedMessage() {
        return encryptedMessage;
    }

    public void setEncryptedMessage(String encryptedMessage) {
        this.encryptedMessage = encryptedMessage;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getDerivedKey() {
        return derivedKey;
    }

    public void setDerivedKey(byte[] derivedKey) {
        this.derivedKey = derivedKey;
    }

    public static Builder with() {
        return new Builder();
    }

    public static final class Builder {
        private EncryptionData encryptionData;

        private Builder() {
            encryptionData = new EncryptionData();
        }

        public Builder encryptedMessage(String encryptedMessage) {
            encryptionData.setEncryptedMessage(encryptedMessage);
            return this;
        }

        public Builder publicKey(String publicKey) {
            encryptionData.setPublicKey(publicKey);
            return this;
        }

        public Builder derivedKey(byte[] derivedKey) {
            encryptionData.setDerivedKey(derivedKey);
            return this;
        }

        public EncryptionData build() {
            return encryptionData;
        }
    }
}
