package com.example.appattest.controller;

import com.example.appattest.model.ChallengeResponse;
import com.example.appattest.model.RegistrationRequest;
import com.example.appattest.service.AttestationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

@RestController
@RequestMapping("/api/attest")
public class AttestationController {
    private final AttestationService service;

    public AttestationController(AttestationService service) {
        this.service = service;
    }

    // Generate a challenge first
    @GetMapping("/challenge")
    public String getChallenge() {
        return service.generateChallenge();
    }

    // Then generate a fresh challenge for the register functionality
    @GetMapping("/register/challenge")
    public ResponseEntity<ChallengeResponse> getRegistrationChallenge(@RequestParam String keyId) throws Exception {
        byte[] hash = service.generateRegistrationChallenge(keyId);
        return ResponseEntity.ok(new ChallengeResponse(
                java.util.Base64.getEncoder().encodeToString(hash)
        ));
    }

    // Use the challenge created above along with the attestation object from Apple to register
    @PostMapping("/register")
    public ResponseEntity<String> registerKey(@RequestBody RegistrationRequest req) {
        boolean ok = service.verifyAndRegisterKey(
                req.getKeyId(),
                java.util.Base64.getDecoder().decode(req.getAttestationObject()),
                req.getClientDataHash()
        );
        return ok
                ? ResponseEntity.ok("Registered")
                : ResponseEntity.badRequest().body("Invalid attestation");
    }

    // Finally verify the assertion
    @PostMapping("/verify")
    public ResponseEntity<String> verifyAssertion(
            @RequestHeader("X-App-Attest-KeyId") String keyId,
            @RequestHeader("X-App-Attest-Nonce") String nonceB64,
            @RequestHeader("X-App-Attest-Assertion") String assertionB64
    ) {
        byte[] nonce     = Base64.getDecoder().decode(nonceB64);
        byte[] assertion = Base64.getDecoder().decode(assertionB64);

        boolean ok = service.verifyAssertion(
                assertion, keyId,
                nonce
        );
        if (!ok) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid attestation");
        }
        return ResponseEntity.ok("Attestation valid");
    }
}