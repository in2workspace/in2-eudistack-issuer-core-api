package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.service.CertificateService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateServiceImpl implements CertificateService {
    private final AccessTokenService accessTokenService;

    @Override
    public Mono<String> getOrganizationIdFromCertificate(String cert){
        return extractClientCertificate(cert)
                .flatMap(this::extractOrganizationIdFromCert);
                //.flatMap(accessTokenService::getOrganizationId);
    }

    public Mono<X509Certificate> extractClientCertificate(String cert) {
        return Mono.justOrEmpty(cert)
                .flatMap(encodedCert -> {
                    try {
                        // Clean the certificate by removing PEM headers and any whitespace or newlines
                        String cleanedCert = encodedCert
                                .replaceAll("-----BEGIN CERTIFICATE-----", "")
                                .replaceAll("-----END CERTIFICATE-----", "")
                                .replaceAll("\\s+", ""); // Remove any whitespace

                        // Decode the cleaned Base64 encoded certificate
                        byte[] decodedBytes = Base64.getDecoder().decode(cleanedCert);

                        // Convert bytes to X509Certificate
                        CertificateFactory factory = CertificateFactory.getInstance("X.509");
                        X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decodedBytes));

                        // Return the certificate wrapped in a Mono
                        return Mono.just(certificate);
                    } catch (CertificateException | IllegalArgumentException e) {
                        // Handle errors by returning a Mono.error
                        return Mono.error(new RuntimeException("Invalid certificate format", e));
                    }
                });
    }

    private Mono<String> validateCertWithAuthServer (X509Certificate cert){
        // call to keycloak to get a token
        return Mono.just("test");
    }

    private Mono<String> extractOrganizationIdFromCert(X509Certificate cert) {
        return Mono.fromCallable(() -> {
            X500Principal principal = cert.getSubjectX500Principal();
            X500Name x500Name = new X500Name(principal.getName());

            // OID for the attribute we are looking for (2.5.4.97)
            ASN1ObjectIdentifier organizationIdentifierOID = new ASN1ObjectIdentifier("2.5.4.97");

            for (RDN rdn : x500Name.getRDNs(organizationIdentifierOID)) {
                for (AttributeTypeAndValue atv : rdn.getTypesAndValues()) {
                    if (atv.getType().equals(organizationIdentifierOID)) {
                        return atv.getValue().toString();
                    }
                }
            }
            throw new RuntimeException("Organization ID not found in the certificate");
        });
    }
}
