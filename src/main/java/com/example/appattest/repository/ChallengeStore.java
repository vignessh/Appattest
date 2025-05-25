package com.example.appattest.repository;

import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory store for one-time challenges.
 */
@Component
public class ChallengeStore {
    private final Set<String> challenges = ConcurrentHashMap.newKeySet();

    /** Store a new challenge. */
    public void store(String challenge) {
        challenges.add(challenge);
    }

    /**
     * Consume and remove a challenge, returning true if it existed.
     */
    public boolean consume(String challenge) {
        return challenges.remove(challenge);
    }
}