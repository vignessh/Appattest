package com.example.appattest.service;

import com.example.appattest.repository.ChallengeStore;
import com.example.appattest.repository.KeyRegistry;
import com.example.appattest.validator.CertificateChain;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AttestationService {
    // These need to be persisted; in-memory will not survive pod restarts or when running as a cluster
    private final ConcurrentHashMap<String, byte[]> publicKeys = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, byte[]> assertionChallenges = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, byte[]> registrationChallenges = new ConcurrentHashMap<>();

    static { Security.addProvider(new BouncyCastleFipsProvider()); }

    private final String expectedBundleId;
    private final ChallengeStore store;
    private final KeyRegistry registry;

    public AttestationService(
            @Value("${attestation.bundleId}") String bundleId,
            ChallengeStore store,
            KeyRegistry registry) {
        this.expectedBundleId = bundleId;
        this.store = store;
        this.registry = registry;
    }

    // Generate 32-byte challenge
    public String generateChallenge() {
        byte[] c = new byte[32]; new SecureRandom().nextBytes(c);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(c);
        store.store(challenge);
        return challenge;
    }

    // Generate SHA-256 hash of keyId for registration
    public byte[] generateRegistrationChallenge(String keyId) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(keyId.getBytes());
        registrationChallenges.put(keyId, hash);
        return hash;
    }

    // Verify initial attestKey() attestation and register public key
    public boolean verifyAndRegisterKey(byte[] attObj, String clientDataHashB64) {
        try {
            byte[] expectedHash = registrationChallenges.get(keyId);
            if (expectedHash == null || !Arrays.equals(expectedHash, Base64.getDecoder().decode(clientDataHashB64))) {
                return false;
            }
            CBORObject cose = CBORObject.DecodeFromBytes(attObj);
            byte[] payload = cose.get(2).GetByteString();
            CBORObject claims = CBORObject.DecodeFromBytes(payload);
            if (!CertificateChain.from(attObj).verify()) {
                return false;
            }
            byte[] pubKeyBytes = claims.get(CBORObject.FromString("publicKey")).GetByteString();
            registry.register(keyId, pubKeyBytes);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // Verify getAssertion() COSE_Sign1
    public boolean verifyAssertion(String keyId, byte[] assertionCbor, byte[] clientChallenge) {
        byte[] stored = assertionChallenges.get(keyId);
        if (stored == null || !Arrays.equals(stored, clientChallenge)) return false;
        assertionChallenges.remove(keyId);
        try {
            CBORObject cose = CBORObject.DecodeFromBytes(assertionCbor);
            byte[] payload = cose.get(2).GetByteString();
            byte[] signature = cose.get(3).GetByteString();
            CBORObject claims = CBORObject.DecodeFromBytes(payload);
            if (!Arrays.equals(claims.get(CBORObject.FromString("nonce")).GetByteString(), clientChallenge)) {
                return false;
            }
            if (!expectedBundleId.equals(claims.get(CBORObject.FromString("bundleIdentifier")).AsString())) {
                return false;
            }
            byte[] keyBytes = publicKeys.get(keyId);
            PublicKey pk = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(keyBytes));
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(pk);
            sig.update(payload);
            return sig.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

}