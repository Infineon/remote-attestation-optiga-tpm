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

package com.ifx.server.service;

import com.ifx.server.entity.User;
import com.ifx.server.model.*;
import com.ifx.server.repository.UserRepository;
import com.ifx.server.service.security.StatefulAuthService;
import com.ifx.server.service.security.UserRepositoryService;
import com.ifx.server.service.security.UserValidator;
import com.ifx.server.tss.CertificationAuthority;
import com.ifx.server.tss.TPMEngine;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestBody;
import tss.tpm.TPMS_QUOTE_INFO;
import tss.tpm.TPM_ALG_ID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.IntStream;

import static com.ifx.server.tss.TPMEngine.*;

@Service
public class CoreService {

    @Autowired
    private CertificationAuthority caManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserValidator userValidator;
    @Autowired
    private UserRepositoryService userService;
    @Autowired
    private StatefulAuthService authService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    private SimpMessagingTemplate simpMessagingTemplate;

    public CoreService() {
    }

    static public String printCertificate(X509Certificate c) {
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

    private String viewAddModelAttributeUsername(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof AnonymousAuthenticationToken == false) {
            model.addAttribute("username", " " + authentication.getName() + " | Log me out");
            return authentication.getName();
        }
        return null;
    }

    public String viewHome(Model model) {
        viewAddModelAttributeUsername(model);
        return "home";
    }

    public String viewEntry(Model model) {
        viewAddModelAttributeUsername(model);
        model.addAttribute("userForm", new User());
        model.addAttribute("userCount", userRepository.count());
        return "entry";
    }

    public String viewDashboard(Model model) {
        String username = viewAddModelAttributeUsername(model);
        User user = userRepository.findByUsername(username);
        AttuneResp attune = new AttuneResp(user.getEkCrt(), user.getEkCrtAttest(), user.getAkPub(),
                user.getAkName(), user.getMeasureList(), fromStr2IntArray(user.getSha1Bank()),
                fromStr2IntArray(user.getSha256Bank()), fromStr2StrArray(user.getPcrs()), null);
        model.addAttribute("attune", attune);

        AtelicResp atelic = new AtelicResp(user.getQualification(), null);
        model.addAttribute("atelic", atelic);

        CaCerts ca = new CaCerts();
        ca.setRootCAText(caManager.getCA().getRootCAText());
        ca.setRootCAAttest(caManager.getCA().getRootCAAttest());
        model.addAttribute("caCerts", ca);

        return "dashboard";
    }

    public Response<String> restPing() {
        return new Response<String>(Response.STATUS_OK, "Hello Client");
    }

    public Response<String> restGetUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return new Response<String>(Response.STATUS_OK, authentication.getName());
    }

    public Response<String> restUserRegistration(User userForm, BindingResult bindingResult) {
        userValidator.validate(userForm, bindingResult);

        if (bindingResult.hasErrors()) {
            return new Response<String>(Response.STATUS_ERROR, null);
        }

        userService.save(userForm);

        return new Response<String>(Response.STATUS_OK, null);
    }

    public Response<String> restUserSignIn(User userForm) {
        try {
            if (authService.autoLogin(userForm.getUsername(), userForm.getPassword())) {
                return new Response<String>(Response.STATUS_OK, null);
            }
        } catch (BadCredentialsException e) {
            return new Response<String>(Response.STATUS_ERROR, e.toString());
        } catch (UsernameNotFoundException e) {
            return new Response<String>(Response.STATUS_ERROR, e.toString());
        } catch (Exception e) {
            return new Response<String>(Response.STATUS_ERROR, e.toString());
        }
        return new Response<String>(Response.STATUS_ERROR, null);
    }

    public Response<String> restUserSignOut(HttpServletRequest request) {
        try {
            SecurityContextHolder.clearContext();
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            return new Response<String>(Response.STATUS_OK, null);
        } catch (Exception e) {
            return new Response<String>(Response.STATUS_ERROR, null);
        }
    }

    public Response<Integer> restError(HttpServletResponse response) {
        return new Response<Integer>(Response.STATUS_OK, response.getStatus());
    }

    public Response<String> restAttune(@RequestBody Attune attune) {
        try {
            User user = userRepository.findByUsername(attune.getUsername());
            int sorted_pcrs_i = 0;
            int unsorted_pcrs_offset = 0;
            boolean toSort = false;
            String[] unsorted_pcrs = null;
            String[] sorted_pcrs = null;
            int[] sorted_sha1Bank = null;
            int[] sorted_sha2Bank = null;
            String computePcrSha1 = null;
            String computePcrSha256 = null;

            if (user == null || !passwordEncoder.matches(attune.getPassword(),user.getPassword())) {
                return new Response<String>(Response.STATUS_ERROR, "invalid username or password");
            }
            user.setAkPub(attune.getAkPub());
            user.setAkName(TPMEngine.computePubKeyName(attune.getAkPub()));
            user.setEkCrt(attune.getEkCrt());
            user.setEkCrtAttest("Failed");

            if (attune.getImaTemplate() != null) {
                List<IMATemplate> IMATemplates = TPMEngine.parseLinuxMeasurements(attune.getImaTemplate(), PLATFORM_PCR);
                String measurementList = TPMEngine.printIMATemplate(IMATemplates);
                computePcrSha1 = Hex.toHexString(TPMEngine.computePcrSha1(IMATemplates));
                computePcrSha256 = Hex.toHexString(TPMEngine.computePcrSha256(IMATemplates));

                user.setMeasureTemplate(attune.getImaTemplate());
                user.setMeasureList(measurementList);
            }

            if (attune.getEkCrt() != null) {
                byte[] crt_der = Hex.decode(attune.getEkCrt());
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                ByteArrayInputStream bytes = new ByteArrayInputStream(crt_der);
                X509Certificate eKCert = (X509Certificate)certFactory.generateCertificate(bytes);
                RSAPublicKey key = (RSAPublicKey)eKCert.getPublicKey();
                user.setEkCrt(printCertificate(eKCert));
                user.setEkPub(Hex.toHexString(key.getModulus().toByteArray()));

                caManager.verify(eKCert);
                user.setEkCrtAttest("Passed");
            }

            /**
             * Sorting of SHA1 & SHA256 bank indexes.
             * This is necessary due to tpm hardware behavior.
             * TPM hashing sequence will follow the order of
             * smallest PCR index to biggest PCR index.
             * Since sha1Bank/sha256Bank input is by human so error-prone.
             * Here we check if sha1Bank/sha256Bank input follows such order.
             * Otherwise, lets sort the PCR index and digest array accordingly
             */
            if (attune.getPcrs() != null) {
                unsorted_pcrs = attune.getPcrs();
                sorted_pcrs = new String[unsorted_pcrs.length];
                toSort = true; // a bit foolish to sort even when it is already sorted ¯\_(ツ)_/¯
            } else {
                user.setPcrs(null);
            }

            if (attune.getSha1Bank() != null && attune.getSha1Bank().length != 0) {
                final int[] sha1Bank = attune.getSha1Bank();

                if (toSort) {
                    String[] sha1PCRValue = Arrays.copyOfRange(unsorted_pcrs, 0, sha1Bank.length);
                    unsorted_pcrs_offset = sha1Bank.length;

                    int[] sortedIndices = IntStream.range(0, sha1Bank.length) // first create an index table
                            .boxed().sorted((i, j) -> {
                                if (sha1Bank[i] == sha1Bank[j])
                                    return 0;
                                if (sha1Bank[i] < sha1Bank[j])
                                    return -1;
                                else
                                    return 1;
                            })
                            .mapToInt(ele -> ele).toArray();
                    for (int i = 0; i < sortedIndices.length; i++) {
                        sorted_pcrs[sorted_pcrs_i++] = sha1PCRValue[sortedIndices[i]];
                    }
                }
                sorted_sha1Bank = IntStream.of(sha1Bank).boxed().sorted(Comparator.naturalOrder()).mapToInt(i -> i).toArray();
                user.setSha1Bank(Arrays.toString(sorted_sha1Bank));

                /* Check PCR10 same as template re-compute value */
                if (computePcrSha1 != null) {
                    for (int i = 0; i < sorted_sha1Bank.length; i++) {
                        if (sorted_sha1Bank[i] == TPMEngine.PLATFORM_PCR) {
                            if (!sorted_pcrs[i].equalsIgnoreCase(computePcrSha1)) {
                                return new Response<String>(Response.STATUS_ERROR, "SHA1 PCR-10 value mismatch with template re-computed value (maybe you did a restart instead of shutdown)");
                            }
                        }
                    }
                }
            } else
                user.setSha1Bank(null);
            if (attune.getSha256Bank() != null && attune.getSha256Bank().length != 0) {
                int[] sha2Bank = attune.getSha256Bank();
                int sha256_start_i = sorted_pcrs_i;

                if (toSort) {
                    String[] sha2PCRValue = Arrays.copyOfRange(unsorted_pcrs, unsorted_pcrs_offset, unsorted_pcrs.length);

                    int[] sortedIndices = IntStream.range(0, sha2Bank.length) // first create an index table
                            .boxed().sorted((i, j) -> {
                                if (sha2Bank[i] == sha2Bank[j])
                                    return 0;
                                if (sha2Bank[i] < sha2Bank[j])
                                    return -1;
                                else
                                    return 1;
                            })
                            .mapToInt(ele -> ele).toArray();
                    for (int i = 0; i < sortedIndices.length; i++) {
                        sorted_pcrs[sorted_pcrs_i++] = sha2PCRValue[sortedIndices[i]];
                    }
                }
                sorted_sha2Bank = IntStream.of(sha2Bank).boxed().sorted(Comparator.naturalOrder()).mapToInt(i -> i).toArray();
                user.setSha256Bank(Arrays.toString(sorted_sha2Bank));

                /* Check PCR10 same as template re-compute value */
                if (computePcrSha256 != null) {
                    for (int i = 0; i < sorted_sha2Bank.length; i++) {
                        if (sorted_sha2Bank[i] == TPMEngine.PLATFORM_PCR) {
                            if (!sorted_pcrs[sha256_start_i + i].equalsIgnoreCase(computePcrSha256)) {
                                return new Response<String>(Response.STATUS_ERROR, "SHA256 PCR-10 value mismatch with template re-computed value (maybe you did a restart instead of shutdown)");
                            }
                        }
                    }
                }
            } else
                user.setSha256Bank(null);
            if (toSort)
                user.setPcrs(Arrays.toString(sorted_pcrs));
            /**
             * Sorting END
             */

            userRepository.save(user);

            /**
             * Send response to active clients via websocket
             */
            try {
                AttuneResp resp = new AttuneResp(user.getEkCrt(), user.getEkCrtAttest(), user.getAkPub(), user.getAkName(),
                        user.getMeasureList(), sorted_sha1Bank, sorted_sha2Bank, sorted_pcrs, new String[] {computePcrSha1, computePcrSha256});
                simpMessagingTemplate.convertAndSendToUser(user.getUsername(), "/topic/private-test",
                        new Response<AttuneResp>(Response.STATUS_OK, resp));
            } catch (Exception e) {
                // ignore
            }

            /**
             * Respond to REST service
             */
            return new Response<String>(Response.STATUS_OK, null);
        } catch (Exception e) {
            return new Response<String>(Response.STATUS_ERROR, e.toString());
        }
    }

    public Response<AtelicResp> restAtelicSample(@RequestBody Atelic atelic) {
        try {
            User user = userRepository.findByUsername(atelic.getUsername());
            if (user == null || !passwordEncoder.matches(atelic.getPassword(),user.getPassword())) {
                return new Response<AtelicResp>(Response.STATUS_ERROR, "invalid username or password", null);
            }

            String qualification = "deadbeef";
            user.setQualification(qualification);
            userRepository.save(user);

            AtelicResp atelicResp = new AtelicResp(qualification, null);
            /**
             * Send response to active clients via websocket
             */
            try {
                simpMessagingTemplate.convertAndSendToUser(atelic.getUsername(), "/topic/private-test",
                        new Response<AtelicResp>(Response.STATUS_OK, atelicResp));
            } catch (Exception e) {
                // ignore
            }

            /**
             * Respond to REST service
             */
            return new Response<AtelicResp>(Response.STATUS_OK, null, atelicResp);
        } catch (Exception e) {
            return new Response<AtelicResp>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    public Response<AtelicResp> restAtelic(@RequestBody Atelic atelic) {
        try {
            User user = userRepository.findByUsername(atelic.getUsername());
            if (user == null || !passwordEncoder.matches(atelic.getPassword(),user.getPassword())) {
                return new Response<AtelicResp>(Response.STATUS_ERROR, "invalid username or password", null);
            }
            String qualification = TPMEngine.getQualification();
            user.setQualification(qualification);
            userRepository.save(user);

            AtelicResp atelicResp = new AtelicResp(qualification, null);
            if (user.getEkPub() != null && user.getAkName() != null &&
                    user.getEkPub() != "" && user.getAkName() != "") {
                // Encrypted qualification
                String credential = TPMEngine.makeCredential(user.getEkPub(), user.getAkName(), qualification);
                atelicResp.setCredential(credential);
            } else {
                // qualification in plain
                atelicResp.setQualification(qualification);
            }

            /**
             * Send response to active clients via websocket
             */
            try {
                simpMessagingTemplate.convertAndSendToUser(atelic.getUsername(), "/topic/private-test",
                        new Response<AtelicResp>(Response.STATUS_OK, null, atelicResp));
            } catch (Exception e) {
                // ignore
            }

            /**
             * Respond to REST service
             */
            return new Response<AtelicResp>(Response.STATUS_OK, null, atelicResp);
        } catch (Exception e) {
            return new Response<AtelicResp>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    public Response<String> restAttest(@RequestBody Attest attest) {
        try {
            User user = userRepository.findByUsername(attest.getUsername());
            if (user == null || !passwordEncoder.matches(attest.getPassword(),user.getPassword())) {
                return new Response<String>(Response.STATUS_ERROR, "invalid username or password");
            }
            int[] sha1Bank = fromStr2IntArray(user.getSha1Bank());
            int[] sha256Bank = fromStr2IntArray(user.getSha256Bank());
            String[] pcrs = fromStr2StrArray(user.getPcrs());

            /**
             *  PCR10 is computed using the IMA template.
             *  Here we take the attest.template as ordering reference.
             *  Now arrange the order of attune.template to match with the reference
             *  Compute the SHA1 & SHA256 digest of the re-ordered template
             *  Use the computed digests as good reference and check it against the quote
             */
            List<IMATemplate> toOrder = TPMEngine.parseLinuxMeasurements(user.getMeasureTemplate(), 10);
            List<IMATemplate> orderRef = TPMEngine.parseLinuxMeasurements(attest.getImaTemplate(), 10);
            List<IMATemplate> ordered = orderIMATemplate(toOrder, orderRef);
            String computedPcrSha1 = Hex.toHexString(TPMEngine.computePcrSha1(ordered));
            String computedPcrSha256 = Hex.toHexString(TPMEngine.computePcrSha256(ordered));
            String measureList = TPMEngine.printIMATemplate(orderRef);
            for (int i = 0; i < sha1Bank.length; i++) {
                if (sha1Bank[i] == TPMEngine.PLATFORM_PCR) {
                    pcrs[i] = computedPcrSha1;
                }
            }
            for (int i = 0; i < sha256Bank.length; i++) {
                if (sha256Bank[i] == TPMEngine.PLATFORM_PCR) {
                    pcrs[sha1Bank.length + i] = computedPcrSha256;
                }
            }

            TPMEngine tpm = new TPMEngine();
            if (tpm.import_publickey_pcr(user.getAkPub(), sha1Bank, sha256Bank, pcrs) != true) {
                return new Response<String>(Response.STATUS_ERROR, "bad public key or pcr values format");
            }
            if (tpm.import_qualification(user.getQualification()) != true) {
                return new Response<String>(Response.STATUS_ERROR, "bad qualification format");
            }
            if (tpm.import_quote_signature(attest.getQuote(), attest.getSignature()) != true) {
                return new Response<String>(Response.STATUS_ERROR, "bad quote or signature format");
            }

            AttestResp resp = new AttestResp(attest.getQuote(), attest.getSignature(),
                    Instant.now().toEpochMilli(), tpm.quote.quoted.clockInfo.clock,
                    tpm.quote.quoted.firmwareVersion, null, null,
                    sha1Bank, sha256Bank, pcrs, Hex.toHexString(tpm.quote.quoted.extraData),
                    Hex.toHexString(((TPMS_QUOTE_INFO)tpm.quote.quoted.attested).pcrDigest),
                    Hex.toHexString(tpm.computeExpectedPcrsDigest()),
                    Hex.toHexString(tpm.quote.quoted.qualifiedSigner), measureList, null);

            for (int i = 0; i < ((TPMS_QUOTE_INFO)tpm.quote.quoted.attested).pcrSelect.length; i++) {
                if (((TPMS_QUOTE_INFO)tpm.quote.quoted.attested).pcrSelect[i].hash == TPM_ALG_ID.SHA1) {
                    int[] pcrSelect = tpm.pcrBitMap(((TPMS_QUOTE_INFO)tpm.quote.quoted.attested).pcrSelect[i].pcrSelect);
                    resp.setSha1Bank(pcrSelect);
                } else if (((TPMS_QUOTE_INFO)tpm.quote.quoted.attested).pcrSelect[i].hash == TPM_ALG_ID.SHA256) {
                    int[] pcrSelect = tpm.pcrBitMap(((TPMS_QUOTE_INFO)tpm.quote.quoted.attested).pcrSelect[i].pcrSelect);
                    resp.setSha256Bank(pcrSelect);
                }
            }

            /**
             * Execute attestation, check quote and signature
             *
             * Send response to active clients via websocket
             * &
             * Respond to REST service
             */
            if (tpm.attest() != true) {
                try {
                    resp.setOutcome("Error in signature, platform measurement, or qualification data");
                    simpMessagingTemplate.convertAndSendToUser(attest.getUsername(), "/topic/private-test",
                            new Response<AttestResp>(Response.STATUS_ERROR, resp));
                } catch (Exception e) {
                    // ignore
                }
                return new Response<String>(Response.STATUS_ERROR, "Error in signature, platform measurement, or qualification data");
            } else {
                try {
                    resp.setOutcome("Passed");
                    simpMessagingTemplate.convertAndSendToUser(attest.getUsername(), "/topic/private-test",
                            new Response<AttestResp>(Response.STATUS_OK, resp));
                } catch (Exception e) {
                    // ignore
                }
                return new Response<String>(Response.STATUS_OK, "passed");
            }
        } catch (Exception e) {
            return new Response<String>(Response.STATUS_ERROR, e.toString());
        }
    }
}
