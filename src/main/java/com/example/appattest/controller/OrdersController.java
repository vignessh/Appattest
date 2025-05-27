package com.example.appattest.controller;

import com.example.appattest.model.OrderRequest;
import com.example.appattest.model.OrderResponse;
import com.example.appattest.service.AttestationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

@RestController
@RequestMapping("/api/orders")
public class OrdersController {
    private final AttestationService attestService;

    public OrdersController(AttestationService attestService) {
        this.attestService = attestService;
    }

    // Sample endpoint that is protected by the attestation
    @PostMapping
    public ResponseEntity<OrderResponse> createOrder(
            @RequestHeader("Authorization") String authHeader,
            @RequestHeader("X-App-Attest-KeyId") String keyId,
            @RequestHeader("X-App-Attest-Nonce") String nonceB64,
            @RequestHeader("X-App-Attest-Assertion") String assertionB64,
            @RequestBody OrderRequest orderReq
    ) {
        // 1. Verify bearer token (not shown)

        // 2. Verify App Attest assertion
        byte[] nonce     = Base64.getDecoder().decode(nonceB64);
        byte[] assertion = Base64.getDecoder().decode(assertionB64);
        if (!attestService.verifyAssertion(assertion, keyId, nonce)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // 3. Proceed with business logic
        OrderResponse resp = new OrderResponse();
        resp.setOrderId("12345");
        resp.setStatus("Created");
        return ResponseEntity.ok(resp);
    }
}