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

import com.ifx.server.model.IMATemplate;
import org.bouncycastle.util.encoders.Hex;
import tss.*;
import tss.tpm.*;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import static tss.Crypto.hash;

public class TPMEngine {

    // Default TPM PCR index used by Linux Integrity Measure Architecture
    public static final int PLATFORM_PCR = 10;

    public PCR_ReadResponse pcrs;
    public byte[] qualification;
    public TPMT_PUBLIC trustedPK;
    public QuoteResponse quote;

    public TPMEngine() {
    }

    /**
     * Import challenge random string, also known as a 'qualification'
     * @param qualification
     * @return success or fail
     */
    public boolean import_qualification(String qualification) {
        try {
            /**
             * Get qualification
             */
            this.qualification = hexStringToByteArray(qualification);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Construct TPMT_PUBLIC & PCR_ReadResponse
     * Supports asymmetric cryptography key TPMS_SIG_SCHEME_RSASSA (SHA256) only
     * @param pubKey
     * @param sha1Bank
     * @param sha256Bank
     * @param pcrs
     * @return success or fail
     */
    public boolean import_publickey_pcr(String pubKey, int[] sha1Bank, int[] sha256Bank, String[] pcrs) {
        try {
            /**
             * Generate TPMT_PUBLIC
             */
            byte[] bArray = hexStringToByteArray(pubKey);
            InByteBuf inBuf = new InByteBuf(bArray);
            inBuf.readInt(2); // skip length of payload
            trustedPK = new TPMT_PUBLIC();
            trustedPK.initFromTpm(inBuf);
            /*
             A few attributes are missing and required to generate a usable TPMT_PUBLIC:
             - TPMS_SIG_SCHEME_RSASSA and TPM_ALG_ID.SHA256 to determine the pcr hash algorithm
             - Exponent for signature verification
             */
            trustedPK.parameters = new TPMS_RSA_PARMS(TPMT_SYM_DEF_OBJECT.nullObject(), new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256), 2048, 65537);

            /**
             * Generate PCR_ReadResponse
             */
            this.pcrs = new PCR_ReadResponse();
            this.pcrs.pcrUpdateCounter = 0;
            if (sha1Bank != null && sha256Bank != null) {
                this.pcrs.pcrSelectionOut = new TPMS_PCR_SELECTION[]{
                        new TPMS_PCR_SELECTION(TPM_ALG_ID.SHA1, sha1Bank),
                        new TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, sha256Bank)
                };
            } else if (sha1Bank != null) {
                this.pcrs.pcrSelectionOut = new TPMS_PCR_SELECTION[]{
                        new TPMS_PCR_SELECTION(TPM_ALG_ID.SHA1, sha1Bank),
                };
            } else if (sha256Bank != null) {
                this.pcrs.pcrSelectionOut = new TPMS_PCR_SELECTION[]{
                        new TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, sha256Bank)
                };
            }
            this.pcrs.pcrValues = new TPM2B_DIGEST[pcrs.length];
            for (int i = 0; i < pcrs.length; i++) {
                this.pcrs.pcrValues[i] = new TPM2B_DIGEST(hexStringToByteArray(pcrs[i]));
            };

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Construct QuoteResponse
     * @param quote
     * @param sig
     * @return success or fail
     */
    public boolean import_quote_signature(String quote, String sig) {
        try {
            byte[] bArray = hexStringToByteArray(
                    String.format("%04x", quote.length()/2) // quote length
                            + quote // Quote
                            + sig); // Signature
            InByteBuf inBuf = new InByteBuf(bArray);

            this.quote = new QuoteResponse();
            this.quote.initFromTpm(inBuf);

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean attest() {
        try {
            /**
             * Attestation
             */
            return trustedPK.validateQuote(pcrs, qualification, quote);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Calculate PCRs digest
     * @return digest
     */
    public byte[] computeExpectedPcrsDigest() {
        OutByteBuf pcrBuf = new OutByteBuf();

        for(int j = 0; j < pcrs.pcrValues.length; ++j) {
            pcrBuf.write(pcrs.pcrValues[j].buffer);
        }

        TPM_ALG_ID hashAlg = Crypto.getSigningHashAlg(trustedPK);
        return hash(hashAlg, pcrBuf.getBuf());
    }

    /***************************************************************
     * Static methods
     **************************************************************/

    /**
     * Get random challenge, also known as a "qualification"
     * @return random string
     */
    public static String getQualification() {
        byte[] ba = Helpers.getRandom(10);
        return byteArrayToHexString(ba);
    }

    /**
     * Encrypt a secret using TPM make credential scheme.
     * Use TPM activate credential to decrypt the secret.
     * @param pubKey EK public key for encryption
     * @param keyName AK key's name
     * @param secret
     * @return credential blob
     */
    public static String makeCredential(String pubKey, String keyName, String secret) {
        try {
            /**
             * Generate TPMT_PUBLIC
             */
            TPMT_PUBLIC trustedPK = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                    new TPMA_OBJECT(new TPMA_OBJECT[]{TPMA_OBJECT.sign, TPMA_OBJECT.sensitiveDataOrigin, TPMA_OBJECT.userWithAuth}),
                    new byte[0],
                    new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES,  128, TPM_ALG_ID.CFB),
                            new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256), 2048, 65537),
                    new TPM2B_PUBLIC_KEY_RSA(hexStringToByteArray(pubKey)));

            byte[] baKeyName = hexStringToByteArray(keyName);
            byte[] baSecret = hexStringToByteArray(secret);

            /**
             * Generate credential blob
             */
            Tss.ActivationCredential bundle = Tss.createActivationCredential(trustedPK, baKeyName, baSecret);
            byte[] baCredential = bundle.CredentialBlob.toTpm();
            String credential = byteArrayToHexString(baCredential);
            String encSeed = byteArrayToHexString(bundle.Secret);
            /* TPM magic 4B + version 4B + credential length 2B + credential + enc_seed length 2B + enc_seed*/
            String blob = "badcc0de" + "00000001" + String.format("%04x", baCredential.length) +
                    credential + String.format("%04x", bundle.Secret.length) + encSeed;
            return blob;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Decode a raw IMA template, obtained from a Linux machine
     * /sys/kernel/security/ima/binary_runtime_measurements
     * Capture items labelled with matching pcrIndex
     * @param lm template
     * @param pcrIndex 0~23
     * @return List<IMATemplate>
     */
    public static List<IMATemplate> parseLinuxMeasurements(String lm, int pcrIndex) {
        try {
            byte[] blm = hexStringToByteArray(lm);
            InputStream in = new ByteArrayInputStream(blm);
            byte[] tmpBytes = new byte[4];
            List<IMATemplate> imaTemplates = new ArrayList<IMATemplate>();

            if (pcrIndex > 23 || pcrIndex < 0)
                new Exception("invalid PCR index");

            while (in.read(tmpBytes, 0, 4) == 4) {
                int pcrNumber = ByteBuffer.wrap(tmpBytes).order(ByteOrder.nativeOrder()).getInt();
                if (pcrNumber != pcrIndex)
                    continue;

                byte[] hashValue = new byte[20];
                in.read(hashValue, 0, 20);

                in.read(tmpBytes, 0, 4);
                int templateNameSize = ByteBuffer.wrap(tmpBytes).order(ByteOrder.nativeOrder()).getInt();

                byte[] templateName = new byte[templateNameSize];
                in.read(templateName, 0, templateNameSize);

                if (!new String(templateName).equals("ima-sig")) {
                    new Exception("invalid template, only support ima-sig");
                }

                in.read(tmpBytes, 0, 4);
                int contentSize = ByteBuffer.wrap(tmpBytes).order(ByteOrder.nativeOrder()).getInt();

                in.read(tmpBytes, 0, 4);
                int digestSize = ByteBuffer.wrap(tmpBytes).order(ByteOrder.nativeOrder()).getInt();

                int algoNameSize = 0;
                if (digestSize == 26) { // XXXXXX (e.g. "sha1:\0")
                    algoNameSize = 6;
                } else if (digestSize == 40) { //XXXXXXXX (e.g. "sha256:\0")
                    algoNameSize = 8;
                } else {
                    new Exception("invalid hash algorithm, only support sha1 or sha256");
                }

                byte[] algoName = new byte[algoNameSize];
                in.read(algoName, 0, algoNameSize);

                if (new String(algoName).equals("sha1:\0")) {
                    digestSize = 20;
                } else if (new String(algoName).equals("sha256:\0")) {
                    digestSize = 32;
                } else {
                    new Exception("invalid hash algorithm, only support sha1 or sha256");
                }

                byte[] digestValue = null;
                digestValue = new byte[digestSize];
                in.read(digestValue, 0, digestSize);

                in.read(tmpBytes, 0, 4);
                int filePathSize = ByteBuffer.wrap(tmpBytes).order(ByteOrder.nativeOrder()).getInt();

                byte[] filePathValue = new byte[filePathSize];
                in.read(filePathValue, 0, filePathSize);

                in.read(tmpBytes, 0, 4);
                int sigSize = ByteBuffer.wrap(tmpBytes).order(ByteOrder.nativeOrder()).getInt();

                byte[] sigValue = new byte[sigSize];
                in.read(sigValue, 0, sigSize);

                imaTemplates.add(new IMATemplate(pcrNumber, hashValue, new String(templateName),
                        new String(algoName), digestValue, new String(filePathValue), sigValue));
            }
            return imaTemplates;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Convert IMA template to human readable format
     * @param imaTemplates
     * @return string
     */
    public static String printIMATemplate(List<IMATemplate> imaTemplates) {
        try {
            String out = "";
            for (int i = 0; i < imaTemplates.size(); i++) {
                IMATemplate ima = imaTemplates.get(i);
                out += byteArrayToHexString(ima.getHash()) + ": " + ima.getFileName() + "\n";
            }
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Calculate PCR SHA1 bank using template
     * @param imaTemplates
     * @return digest
     */
    public static byte[] computePcrSha1(List<IMATemplate> imaTemplates) {
        try {
            int sha1Len = 20;
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.reset();
            md.update (hexStringToByteArray("0000000000000000000000000000000000000000"), 0, sha1Len);
            md.update (imaTemplates.get(0).getHash(), 0, sha1Len);
            byte[] pcr = md.digest();
            for (int i = 1; i < imaTemplates.size(); i++) {
                md.reset();
                md.update (pcr, 0, sha1Len);
                md.update (imaTemplates.get(i).getHash(), 0, sha1Len);
                pcr = md.digest();
            }
            return pcr;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Calculate PCR SHA256 bank using template
     * @param imaTemplates
     * @return digest
     */
    public static byte[] computePcrSha256(List<IMATemplate> imaTemplates) {
        try {
            int sha1Len = 20;
            int sha256Len = 32;
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] value = hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000");
            md.reset();
            md.update (value, 0, sha256Len);
            System.arraycopy(imaTemplates.get(0).getHash(), 0, value, 0, sha1Len);
            md.update (value, 0, sha256Len);
            byte[] pcr = md.digest();
            for (int i = 1; i < imaTemplates.size(); i++) {
                md.reset();
                md.update (pcr, 0, sha256Len);
                System.arraycopy(imaTemplates.get(i).getHash(), 0, value, 0, sha1Len);
                md.update (value, 0, sha256Len);
                pcr = md.digest();
            }
            return pcr;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Re-order IMATemplate content
     * @param toOrder templates to be re-arranged
     * @param orderRef arrangement reference templates
     * @return re-ordered template
     */
    public static List<IMATemplate> orderIMATemplate(List<IMATemplate> toOrder, List<IMATemplate> orderRef) {
        try {
            List<IMATemplate> tidy = new ArrayList<IMATemplate>();
            for (int i = 0; i < orderRef.size(); i++) {
                String ref = Hex.toHexString(orderRef.get(i).getHash());
                IMATemplate found = toOrder.stream()
                        .filter(template -> ref.equals(Hex.toHexString(template.getHash())))
                        .findAny().orElse(null);
                if (found != null)
                    tidy.add(found);
            }
            return tidy;
        } catch (Exception e) {
            return null;
        }

    }

    /**
     * Calculate TPM key's Name according to TPM standard
     * A key's Name is a digest of its public data
     * @param pubKey
     * @return name
     */
    public static String computePubKeyName(String pubKey) {
        byte[] bArray = hexStringToByteArray(pubKey);
        InByteBuf inBuf = new InByteBuf(bArray);
        inBuf.readInt(2); // skip length of payload
        TPMT_PUBLIC pk = new TPMT_PUBLIC();
        pk.initFromTpm(inBuf);
        return byteArrayToHexString(pk.getName());
    }

    /**
     * Convert 3 bytes of PCR selection bitmap to index array
     * x00   x00    x00
     * ^7-0  ^15-8  ^23-16
     * e.g:
     *  pcr3 -> x08 x00 x00
     *  pcr7 -> x80 x00 x00
     * @param pcrSelect
     * @return pcr index array
     */
    public static int[] pcrBitMap(byte[] pcrSelect) {
        if (pcrSelect.length != 3)
            return null;
        ArrayList<Integer> indexes = new ArrayList<Integer>();
        int indexCount = 0;
        int i = 0;
        do {
            byte target = pcrSelect[i];
            for (int j = 0; j < 8; j++) {
                if (((target >> j) & 0x01) == (byte)0x01) {
                    indexes.add(indexCount);
                }
                indexCount++;
            }
        } while (++i < pcrSelect.length);
        return indexes.stream().mapToInt((Integer z) -> z.intValue()).toArray();
    }

    /**
     * Convert string to int array
     * "[0, 1, 2]" -> {0, 1, 2}
     * @param string
     * @return int array
     */
    public static int[] fromStr2IntArray(String string) {
        if (string == null || string == "" || string == "[]") return null;
        String[] strings = string.replace("[", "").replace("]", "").split(", ");
        int result[] = new int[strings.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = Integer.parseInt(strings[i]);
        }
        return result;
    }

    /**
     * Convert string to string array
     * "[a, b, c]" -> {"a", "b", "c"}
     * @param string
     * @return string array
     */
    public static String[] fromStr2StrArray(String string) {
        if (string == null || string == "" || string == "[]") return null;
        String[] result = string.replace("[", "").replace("]", "").split(", ");
        return result;
    }

    /***************************************************************
     * Private methods
     **************************************************************/

    /**
     * Convert hex string to byte array
     * "000102" -> {0x00, 0x01, 0x02}
     * @param s hex string
     * @return byte array
     */
    private static byte[] hexStringToByteArray(String s) {
        return Hex.decode(s);
    }

    /**
     * Convert byte array to hex string
     * {0x00, 0x01, 0x02} -> "000102"
     * @param ba byte array
     * @return hex string
     */
    private static String byteArrayToHexString(byte[] ba) {
        return Hex.toHexString(ba);
    }
}
