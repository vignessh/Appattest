package com.example.appattest.repository;

import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class KeyRegistry {
    private final ConcurrentHashMap<String, PublicKey> keys = new ConcurrentHashMap<>();

    public void register(String keyId, PublicKey publicKey) {
        keys.put(keyId, publicKey);
    }

    public PublicKey get(String keyId) {
        return keys.get(keyId);
    }
}