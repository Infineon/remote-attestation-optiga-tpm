/**
* MIT License
*
* Copyright (c) 2020 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*/

package com.ifx.server.tss;

import com.ifx.server.model.CaCerts;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Optional;

/**
 * - First the hardcoded issuer certificates will be considered. If there is no matching certs,
 *   the service will attempt to download issuer certificates from trusted sites.
 *   However, this approach is vulnerable to DNS spoofing or DNS cache poisoning attacks
 * - CRL is not checked.
 */
@Service
public class CertificationAuthority {

    private final int CERT_CHAIN_DEPTH_MAX = 5;
    private final String[] TRUSTED_CA_SITES = {"pki.infineon.com"};
    HashMap<String, X509Certificate> CAs;

    @Value("classpath:certificates/*.crt")
    private Resource[] resourceOptigaRootCACert;

    private CaCerts displayCA;

    public CertificationAuthority() {
        CAs = new HashMap<>();
        displayCA = new CaCerts();
    }

    /**
     * This is for dashboard display only. There are multiple valid root certs,
     * so we randomly pick one.
     */
    @PostConstruct
    private void CertificationAuthority() throws Exception {
        try {
            for (Resource resource:resourceOptigaRootCACert) {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                X509Certificate rootCa = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(resource.getInputStream().readAllBytes()));
                verifyAndStoreRootCACert(rootCa);
            }

            Optional<String> firstKey = CAs.keySet().stream().findFirst();
            if (firstKey.isPresent()) {
                X509Certificate cert = CAs.get(firstKey.get());
                displayCA.setRootCACert(cert);
                displayCA.setRootCAAttest("Passed");
                displayCA.setRootCAText(printCert(cert));
            }
        } catch (Exception e) {
            throw new Exception(e.getMessage());
        }
    }

    public CaCerts getDisplayCA() {
        return displayCA;
    }

    public void verify(X509Certificate toe) throws Exception {
        try {
            X509Certificate issuer;
            int depth = CERT_CHAIN_DEPTH_MAX;

            do {
                if (depth-- < 0)
                    throw new Exception("Certificate chain is longer than acceptable length of " + CERT_CHAIN_DEPTH_MAX);

                String toeDN = toe.getSubjectX500Principal().getName();
                String issuerDN = toe.getIssuerX500Principal().getName();

                /* check if we reached the root of the certificate chain */
                if (toeDN.equals(issuerDN)) {
                    issuer = CAs.get(issuerDN);
                    toe.checkValidity();
                    toe.verify(issuer.getPublicKey());
                    break;
                }

                /* do we know the issuer? */
                issuer = CAs.get(issuerDN);

                /* try to download the issuer certificate */
                if (issuer == null) {
                    int i = 0;
                    String link = getIssuerUrl(toe);

                    if (link == null)
                        throw new Exception("Unable to retrieve uri from Authority Information Access field.");

                    for (i = 0; i < TRUSTED_CA_SITES.length; i++) {
                        if (link.startsWith("http://" + TRUSTED_CA_SITES[i]))
                            break;
                        if (link.startsWith("https://" + TRUSTED_CA_SITES[i]))
                            break;
                    }

                    if (i >= TRUSTED_CA_SITES.length)
                        throw new Exception("URI to download issuer's certificate is not trusted.");

                    URL url = new URL(link);
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    issuer = (X509Certificate) certFactory.generateCertificate(url.openStream());
                    if (!issuer.getSubjectX500Principal().getName().equals(issuerDN))
                        throw new Exception("CA server returns bad certificate.");

                    verifyAndStoreIssuerCert(true, toe, issuer);
                } else {
                    verifyAndStoreIssuerCert(false, toe, issuer);
                }

                toe = issuer;
            } while(true);
        } catch (Exception e) {
            // CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
            throw e;
        }
    }

    private static String getIssuerUrl(X509Certificate certificate) throws Exception {

        byte[] bytes = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        ASN1Primitive obj = aIn.readObject();

        AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(obj);

        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {

            GeneralName name = accessDescription.getAccessLocation();
            if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
                continue;
            }

            DERIA5String derStr = DERIA5String.getInstance((ASN1TaggedObject) name.toASN1Primitive(), false);
            return derStr.getString();
        }
        return null;
    }

    static public String printCert(X509Certificate cert) {
        String out = "";

        try {
            out += "Version: V" + cert.getVersion() + ", ";
            out += "Format: " + cert.getType() + "\n";

            try {
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
                out += "Thumbprint: " + Hex.toHexString(messageDigest.digest(cert.getEncoded())) + "\n";
            } catch (NoSuchAlgorithmException e) {
            }

            out += "Serial Number: " + cert.getSerialNumber().toString(16) + "\n";
            out += "Subject: " + cert.getSubjectX500Principal().toString() + "\n";
            out += "Issuer: "+ cert.getIssuerX500Principal().toString() + "\n";
            out += "Validity: [From: " + cert.getNotBefore().toString() +
                    ", To: " + cert.getNotAfter().toString() + "]\n";
            out += "Signature Algorithm: "+ cert.getSigAlgName() + "\n";
            out += "Public Key: "+ cert.getPublicKey().toString() + "\n";
            out += "Signature: "+ Hex.toHexString(cert.getSignature()) + "\n";
        } catch (Exception e) {
        }
        return out;
    }

    /**
     * Verify root CA self-signed certificate and remember the cert
     * @param rootCa
     * @return
     */
    private void verifyAndStoreRootCACert(X509Certificate rootCa) throws Exception {
        if (!rootCa.getIssuerX500Principal().equals(rootCa.getSubjectX500Principal()))
            throw new Exception("root CA cert is not a self-signed cert");
        rootCa.checkValidity();
        rootCa.verify(rootCa.getPublicKey());
        CAs.put(rootCa.getIssuerX500Principal().getName(), rootCa);
    }

    /**
     * Verify child & issuer certificate and remember the issuer certificate
     * @param childCert
     * @param issuerCert
     * @throws Exception
     */
    private void verifyAndStoreIssuerCert(boolean toStore, X509Certificate childCert, X509Certificate issuerCert) throws Exception {
        if (!childCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal()))
            throw new Exception("certificate issuer mismatch");
        childCert.checkValidity();
        issuerCert.checkValidity();
        childCert.verify(issuerCert.getPublicKey());
        if (toStore)
            CAs.put(issuerCert.getSubjectX500Principal().getName(), issuerCert);
    }
}
