package com.example.appattest.model;

public class RegistrationRequest {
    private String keyId;
    private String attestationObject;
    private String clientDataHash;

    public RegistrationRequest() {}
    public String getKeyId() { return keyId; }
    public void setKeyId(String keyId) { this.keyId = keyId; }
    public String getAttestationObject() { return attestationObject; }
    public void setAttestationObject(String attestationObject) { this.attestationObject = attestationObject; }
    public String getClientDataHash() { return clientDataHash; }
    public void setClientDataHash(String clientDataHash) { this.clientDataHash = clientDataHash; }
}