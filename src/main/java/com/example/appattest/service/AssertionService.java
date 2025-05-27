package com.example.appattest.service;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.*;
import com.example.appattest.repository.ChallengeStore;
import com.example.appattest.repository.KeyRegistry;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;

@Service
public class AssertionService {

    private final ChallengeStore assertionStore;
    private final KeyRegistry keyRegistry;

    public AssertionService(ChallengeStore assertionStore, KeyRegistry keyRegistry) {
        this.assertionStore = assertionStore;
        this.keyRegistry = keyRegistry;
    }

    public String generateAssertionChallenge(String keyId) {
        if (keyRegistry.get(keyId) == null) {
            throw new IllegalArgumentException("Unknown keyId");
        }
        byte[] rnd = new byte[32]; new java.security.SecureRandom().nextBytes(rnd);
        String ch = Base64.getUrlEncoder().withoutPadding().encodeToString(rnd);
        assertionStore.store(ch);
        return ch;
    }

    public void verifyAssertion(String assertionB64, String keyId, String originalChallenge) {
        if (!assertionStore.consume(originalChallenge)) {
            throw new IllegalArgumentException("Invalid or expired assertion challenge");
        }
        try {
            var assertion = new Assertion(assertionB64);

            byte[] signedData = assertion.signedData();
            byte[] sigBytes = assertion.signatureBytes();
            String reqKeyId = assertion.keyId();

            if (!keyId.equals(reqKeyId)) {
                throw new IllegalArgumentException("keyId mismatch");
            }
            PublicKey pk = keyRegistry.get(keyId);
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(pk);
            sig.update(signedData);
            if (!sig.verify(sigBytes)) {
                throw new IllegalArgumentException("Assertion signature invalid");
            }
        } catch (Exception e) {
            throw new RuntimeException("Assertion verification failed: " + e.getMessage(), e);
        }
    }
}

class Assertion {
    private final Map<DataItem, DataItem> structure;
    public Assertion(String assertionBase64) throws IOException, CborException {
        byte[] obj = Base64.getDecoder().decode(assertionBase64);
        try (var stream = new ByteArrayInputStream(obj)) {
            structure = (Map) new CborDecoder(stream).decode().getFirst();
        }
    }

    public byte[] signedData() {
        return ((ByteString) structure.get(new UnicodeString("clientData"))).getBytes();
    }

    public byte[] signatureBytes() {
        return ((ByteString) structure.get(new UnicodeString("signature"))).getBytes();
    }

    public String keyId() {
        return ((UnicodeString) structure.get(new UnicodeString("keyId"))).getString();
    }
}