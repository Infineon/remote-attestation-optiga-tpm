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
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;

@Component
public class CertificationAuthority {

    private final int CERT_CHAIN_DEPTH_MAX = 5;

    @Value("classpath:certificates/Infineon-TPM_RSA_Root_CA-C-v01_00-EN.cer")
    private Resource resourceCACrtRootRsa;
    private CaCerts rootCA;
    private HashMap<String, X509Certificate>  issuers;

    public CertificationAuthority() {
        issuers = new HashMap<String, X509Certificate>();
        rootCA = new CaCerts();
    }

    @PostConstruct
    private void initCACert() {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate ca = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(resourceCACrtRootRsa.getInputStream().readAllBytes()));
            ca.checkValidity();
            rootCA.setRootCACert(ca);

            if (verifySignature(rootCA.getRootCACert(), rootCA.getRootCACert()))
                rootCA.setRootCAAttest("Passed");
            else
                rootCA.setRootCAAttest("Failed");

            rootCA.setRootCAText(print(rootCA.getRootCACert()));

            issuers.put(ca.getSubjectDN().getName(), ca);

        } catch (Exception e) {
        }
    }

    /**
     * Return rootCA
     *
     * @return
     */
    public CaCerts getCA() {
        return rootCA;
    }

    /**
     * Output certificate info to String
     *
     * @param c
     * @return
     */
    static public String print(X509Certificate c) {
        String out = "";
        try {
            out += "Version: V" + Integer.toString(c.getVersion()) + ", ";
            out += "Format: " + c.getType() + "\n";
            out += "Subject: " + c.getSubjectDN().toString() + "\n";
            out += "Issuer: "+ c.getIssuerDN().toString() + "\n";
            out += "Validity: [From: " + c.getNotBefore().toString() +
                    ", To: " + c.getNotAfter().toString() + "]\n";
            out += "Signature Algorithm: "+ c.getSigAlgName() + "\n";
            out += "Public Key: "+ c.getPublicKey().toString() + "\n";
            out += "Signature: "+ Hex.toHexString(c.getSignature()) + "\n";
        } catch (Exception e) {
        }
        return out;
    }

    /**
     * Verify certificate
     *
     * @param toVerify
     * @throws Exception
     */
    public void verify(X509Certificate toVerify) throws Exception {
        try {
            HashMap<String, X509Certificate> tmp = new HashMap<String, X509Certificate>();
            X509Certificate issuer;
            X509Certificate toe = toVerify;
            int depth = CERT_CHAIN_DEPTH_MAX;

            do {
                if (depth-- < 0)
                    throw new Exception("Certificate chain is too long.");

                String toeDN = toe.getSubjectDN().getName();
                String issuerDN = toe.getIssuerDN().getName();
                if (toeDN.equals(issuerDN)) { // self-sign
                    X509Certificate rootCrt = rootCA.getRootCACert();
                    toe.verify(rootCrt.getPublicKey());
                    toe.checkValidity();
                    issuers.putAll(tmp);
                    // Reached the root of certificate chain
                    break;
                }

                issuer = issuers.get(issuerDN);
                if (issuer == null) {
                    String link = getUrl(toe);
                    URL url = new URL(link);
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    issuer = (X509Certificate) certFactory.generateCertificate(url.openStream());
                    if (!issuer.getSubjectDN().getName().equals(issuerDN))
                        throw new Exception("CA server returns bad certificate.");
                    tmp.put(issuer.getSubjectDN().getName(), issuer);
                }

                toe.verify(issuer.getPublicKey());
                toe.checkValidity();
                toe = issuer;
            } while(true);
        } catch (Exception e) {
            // CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
            throw e;
        }
    }

    /**
     * Return signer's certificate link
     *
     * @param certificate
     * @return
     * @throws Exception
     */
    private static String getUrl(X509Certificate certificate) throws Exception {

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

    /**
     * Verify x509 certificate
     *
     * @param toVerify
     * @param signingCert
     * @return success or fail
     */
    private static boolean verifySignature(X509Certificate toVerify, X509Certificate signingCert) {
        if (!toVerify.getIssuerDN().equals(signingCert.getSubjectDN())) return false;
        try {
            toVerify.verify(signingCert.getPublicKey());
            return true;
        } catch (Exception e) {
            // CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
            return false;
        }
    }
}
