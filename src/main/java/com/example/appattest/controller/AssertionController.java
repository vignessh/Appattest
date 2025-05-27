package com.example.appattest.controller;

import com.example.appattest.service.AssertionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/assertion")
public class AssertionController {
    private final AssertionService assertionService;

    public AssertionController(AssertionService assertionService) {
        this.assertionService = assertionService;
    }

    @GetMapping("/challenge/{keyId}")
    public String getAssertionChallenge(@PathVariable String keyId) {
        return assertionService.generateAssertionChallenge(keyId);
    }

//    @PostMapping("/response")
//    public ResponseEntity<String> verifyAssertion(@RequestBody AssertionRequest req) {
//        assertionService.verifyAssertion(req.getAssertionObject(), req.getKeyId(), req.getChallenge());
//        return ResponseEntity.ok("Assertion successful: client authenticity verified.");
//    }
}