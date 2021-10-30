package com.joaodartora.echdcrypto.domain;

public class PaymentData {

    private String accountNumber;
    private String version;
    private String nonce;
    private String nonceSignature;
    private String productType;
    private String name;

    public PaymentData() {
    }

    public String getAccountNumber() {
        return accountNumber;
    }

    public void setAccountNumber(String accountNumber) {
        this.accountNumber = accountNumber;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getNonceSignature() {
        return nonceSignature;
    }

    public void setNonceSignature(String nonceSignature) {
        this.nonceSignature = nonceSignature;
    }

    public String getProductType() {
        return productType;
    }

    public void setProductType(String productType) {
        this.productType = productType;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public static Builder with() {
        return new Builder();
    }

    public static final class Builder {
        private PaymentData paymentData;

        private Builder() {
            paymentData = new PaymentData();
        }

        public Builder accountNumber(String accountNumber) {
            paymentData.setAccountNumber(accountNumber);
            return this;
        }

        public Builder version(String version) {
            paymentData.setVersion(version);
            return this;
        }

        public Builder nonce(String nonce) {
            paymentData.setNonce(nonce);
            return this;
        }

        public Builder nonceSignature(String nonceSignature) {
            paymentData.setNonceSignature(nonceSignature);
            return this;
        }

        public Builder productType(String productType) {
            paymentData.setProductType(productType);
            return this;
        }

        public Builder name(String name) {
            paymentData.setName(name);
            return this;
        }

        public PaymentData build() {
            return paymentData;
        }
    }
}
