package com.example.appattest.validator;

import com.upokecenter.cbor.CBORObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CertificateChain {
    private final List<X509Certificate> x509Certificates;
    @Value("classpath:apple-app-attest-root.pem")
    private Resource appleRootCert;

    private X509Certificate loadAppleRootCert() throws Exception {
        try (InputStream in = appleRootCert.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(in);
        }
    }

    public CertificateChain(List<X509Certificate> chain) {
        this.x509Certificates = chain;
    }

    public static CertificateChain from(byte[] attObj) throws Exception {
        CBORObject cose = CBORObject.DecodeFromBytes(attObj);
        CBORObject attStmt = cose.get(CBORObject.FromString("attStmt"));
        CBORObject x5cArray = attStmt.get(CBORObject.FromString("x5c"));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> chain = new ArrayList<>();
        for (CBORObject certItem : x5cArray.getValues()) {
            byte[] der = certItem.GetByteString();
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
            chain.add(cert);
        }
        return new CertificateChain(chain);
    }

    public boolean verify() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        TrustAnchor anchor = new TrustAnchor(loadAppleRootCert(), null);
        PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
        // Check for revocation
        params.setRevocationEnabled(true);

        CertPath cp = cf.generateCertPath(x509Certificates);
        CertPathValidator.getInstance("PKIX").validate(cp, params);
        return true;
    }
}
