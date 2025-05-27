package com.example.appattest.interceptor;

import com.example.appattest.service.AttestationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class AttestationInterceptor implements HandlerInterceptor {

    private final AttestationService service;

    public AttestationInterceptor(AttestationService service) {
        this.service = service;
    }

    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {
        String keyId = request.getHeader("Key-Id");
        String challenge = request.getHeader("Assertion-Challenge");
        String assertion = request.getHeader("Assertion-Object");

        if (keyId == null || challenge == null || assertion == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing App Attest headers");
            return false;
        }

        try {
            // Will throw exception if verification fails
             service.verifyAssertion(assertion.getBytes(), keyId, challenge.getBytes());
            return true;
        } catch (Exception ex) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "App Attest verification failed: " + ex.getMessage());
            return false;
        }
    }
}