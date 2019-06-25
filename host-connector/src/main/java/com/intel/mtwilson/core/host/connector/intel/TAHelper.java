/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.host.connector.intel;

import com.intel.dcsg.cpg.crypto.DigestAlgorithm;
import com.intel.dcsg.cpg.io.ByteArray;
import com.intel.dcsg.cpg.net.IPv4Address;
import com.intel.dcsg.cpg.net.InternetAddress;
import com.intel.dcsg.cpg.crypto.RandomUtil;

import java.io.*;
import java.net.UnknownHostException;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.regex.Pattern;

import javax.xml.bind.JAXBException;

import com.intel.mtwilson.aikqverify.*;
import com.intel.mtwilson.core.common.model.*;
import org.apache.commons.codec.binary.Base64;

import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.crypto.Sha256Digest;

import com.intel.mtwilson.core.common.trustagent.client.jaxrs.TrustAgentClient;
import com.intel.mtwilson.core.common.trustagent.model.TpmQuoteResponse;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.security.cert.CertificateException;
import javax.xml.bind.PropertyException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * In order to use the TAHelper, you need to have attestation-service.properties
 * on your machine.
 *
 * Here are example properties that Jonathan has at
 * C:/Intel/CloudSecurity/attestation-service.properties: *
 * com.intel.mountwilson.as.home=C:/Intel/CloudSecurity/AttestationServiceData/aikverifyhome
 * com.intel.mountwilson.as.aikqverify.cmd=aikqverify.exe
 * com.intel.mountwilson.as.openssl.cmd=openssl.bat
 *
 * The corresponding files must exist. From the above example:
 *
 * C:/Intel/CloudSecurity/AttestationServiceData/aikverifyhome
 * C:/Intel/CloudSecurity/AttestationServiceData/aikverifyhome/data (can be
 * empty, TAHelper will save files there)
 * C:/Intel/CloudSecurity/AttestationServiceData/aikverifyhome/bin contains:
 * aikqverify.exe, cygwin1.dll
 *
 * @author dsmagadx
 */
public class TAHelper {

    private Logger log = LoggerFactory.getLogger(getClass());
    private Pattern pcrNumberPattern = Pattern.compile("[0-9]|[0-1][0-9]|2[0-3]"); // integer 0-23 with optional zero-padding (00, 01, ...)
    private Pattern pcrValuePattern = Pattern.compile("[0-9a-fA-F]+"); // 40-character hex string
    private String pcrNumberUntaint = "[^0-9]";
    private String pcrValueUntaint = "[^0-9a-fA-F]";
    private static final int SHA1_SIZE = 20;
    private static final int SHA256_SIZE = 32;
    private boolean quoteWithIPAddress = true; // to fix issue #1038 we use this secure default
    private String trustedAik = null; // host's AIK in PEM format, for use in verifying quotes (caller retrieves it from database and provides it to us)
    private String[] openSourceHostSpecificModules = {"initrd", "vmlinuz"};
    private HostInfo host;
    boolean isHostWindows;

    /* We need host info to be passed so we can verify the host quote based on the OS and TPM version
     * Based on the host information, the command to call for quote verification will be different
     * These are the 4 combination: Linux/TPM 1.2, Linux/TPM2.0, Windows/TPM1.2, Windows/TPM2.0
     *    
     */
    public TAHelper(HostInfo hostBeingVerified)  {
        this.host = hostBeingVerified;
        isHostWindows = host.getOsName().toLowerCase().contains("microsoft");
    }
    
    public void setTrustedAik(String pem) {
        trustedAik = pem;
    }

    public byte[] getIPAddress(String hostname) throws UnknownHostException {
        byte[] ipaddress;
        InternetAddress address = new InternetAddress(hostname);
        if (address.isIPv4()) {
            IPv4Address ipv4address = new IPv4Address(hostname);
            ipaddress = ipv4address.toByteArray();
            if (ipaddress == null) {
                throw new UnknownHostException(hostname); // throws UnknownHostException
            }
            assert ipaddress.length == 4;
        } else if (address.isIPv6() || address.isHostname()) {
            // resolve it to find the ipv4 address
            InetAddress inetAddress = InetAddress.getByName(hostname); // throws UnknownHostException
            log.info("Resolved hostname {} to address {}", hostname, inetAddress.getHostAddress());
            if (inetAddress instanceof Inet4Address) {
                ipaddress = inetAddress.getAddress();
                assert ipaddress.length == 4;
            } else if (inetAddress instanceof Inet6Address) {
                if (((Inet6Address) inetAddress).isIPv4CompatibleAddress()) {
                    ipaddress = ByteArray.subarray(inetAddress.getAddress(), 12, 4); // the last 4 bytes of of an ipv4-compatible ipv6 address are the ipv4 address (first 12 bytes are zero)
                } else {
                    throw new IllegalArgumentException("mtwilson.tpm.quote.ipv4 is enabled and requires an IPv4-compatible address but host address is IPv6: " + hostname);
                }
            } else {
                throw new IllegalArgumentException("mtwilson.tpm.quote.ipv4 is enabled and requires an IPv4-compatible address but host address is unknown type: " + hostname);
            }
        } else {
            throw new IllegalArgumentException("mtwilson.tpm.quote.ipv4 is enabled and requires an IPv4-compatible address but host address is unknown type: " + hostname);
        }
        return ipaddress;
    }

    public HostManifest getQuoteInformationForHost(String hostname, TrustAgentClient client) throws
             IOException, CertificateException{
        return getQuoteInformationForHost(hostname, client, null);
    }

    // NOTE:  this v2 client method is a little different from the getQuoteInformationForHost for the v1 trust agent because
    //        it hashes the nonce and the ip address together  (instead of replacing the last 4 bytes of the nonce
    //        with the ip address like the v1 does)
    public HostManifest getQuoteInformationForHost(String hostname, TrustAgentClient client, Nonce challenge) throws
            IOException, CertificateException {

        try {
            //  BUG #497  START CODE SNIPPET MOVED TO INTEL HOST AGENT
            byte[] nonce;
            if (challenge == null) {
                nonce = generateNonce(); // 20 random bytes
            } else {
                nonce = challenge.toByteArray(); // issue #4978: use specified nonce, if available
            }

            // to fix issue #1038 we have a new option to put the host ip address in the nonce (we don't send this to the host - the hsot automatically would do the same thing)
            byte[] verifyNonce = nonce; // verifyNonce is what we save to verify against host's tpm quote response
            if (quoteWithIPAddress) {
                // is the hostname a dns name or an ip address?  if it's a dns name we have to resolve it to an ip address
                // see also corresponding code in TrustAgent CreateNonceFileCmd
                byte[] ipaddress = getIPAddress(hostname);
                if (ipaddress == null) {
                    throw new IllegalArgumentException("mtwilson.tpm.quote.ipv4 is enabled but host address cannot be resolved: " + hostname);
                }
                verifyNonce = Sha1Digest.digestOf(nonce).extend(ipaddress).toByteArray();
            }
            // String verifyNonceBase64 = Base64.encodeBase64String(verifyNonce);

            String sessionId = generateSessionId();

            // FIrst let us ensure that we have an AIK cert created on the host before trying to retrieve the quote. The trust agent
            // would verify if a AIK is already present or not. If not it will create a new one.
            X509Util.encodePemCertificate(client.getAik());

            // to fix issue #1038 trust agent relay we send 20 random bytes nonce to the host (base64-encoded) but if mtwilson.tpm.quote.ipaddress is enabled then in our copy we replace the last 4 bytes with the host's ip address, and when the host generates the quote it does the same thing, and we can verify it later
            // we select best PCR bank but we will change to all PCR banks once it's supported
            TpmQuoteResponse tpmQuoteResponse = client.getTpmQuote(nonce, new int[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}, host.getPcrBanks()); // pcrList used to be a comma-separated list passed to this method... but now we are returning a quote with ALL the PCR's ALL THE TIME.
            log.debug("got response from server [" + hostname + "] ");

            log.debug("extracted quote from response: {}", Base64.encodeBase64String(tpmQuoteResponse.quote));


            // for Windows host, we generate a new nonce by sha1(nonce | tag)
            // Now is done for ALL hosts, not only Windows
            if (tpmQuoteResponse.isTagProvisioned) {
                log.debug("tpmQuoteResponse.isTagProvisioned is true");
                verifyNonce = Sha1Digest.digestOf(verifyNonce).extend(tpmQuoteResponse.assetTag).toByteArray();
            }

            RSAPublicKey rsaPublicKey = (RSAPublicKey) tpmQuoteResponse.aik.getPublicKey();

            // Verify if there is TCBMeasurement Data. This data would be available if we are extending the root of trust to applications and data on the OS
            List<String> tcbMeasurementStrings = tpmQuoteResponse.tcbMeasurements;
            logMeasurements(tcbMeasurementStrings);

            log.debug("Event log: {}", tpmQuoteResponse.eventLog); // issue #879
            byte[] eventLogBytes = Base64.decodeBase64(tpmQuoteResponse.eventLog);// issue #879
            log.debug("Decoded event log length: {}", eventLogBytes == null ? null : eventLogBytes.length);// issue #879
            PcrManifest pcrManifest;
            if (eventLogBytes != null) { // issue #879
                String decodedEventLog = new String(eventLogBytes);
                log.debug("Event log retrieved from the host consists of: " + decodedEventLog);

                // Since we need to add the event log details into the pcrManifest, we will pass in that information to the below function
                pcrManifest = verifyQuoteAndGetPcr(sessionId, decodedEventLog, verifyNonce, tpmQuoteResponse.quote, rsaPublicKey);
            } else {
                pcrManifest = verifyQuoteAndGetPcr(sessionId, null, verifyNonce, tpmQuoteResponse.quote, rsaPublicKey); // verify the quote but don't add any event log info to the PcrManifest. // issue #879
                log.debug("Got PCR map");
            }
	    HostManifest hostManifest = new HostManifest();
            if (tcbMeasurementStrings !=null && !tcbMeasurementStrings.isEmpty()) {
                hostManifest.setMeasurementXmls(tcbMeasurementStrings);
            }
            hostManifest.setProvisionedTag(tpmQuoteResponse.assetTag);
            hostManifest.setAikCertificate(tpmQuoteResponse.aik);
            hostManifest.setAssetTagDigest(tpmQuoteResponse.assetTag);
            hostManifest.setPcrManifest(pcrManifest);
            return hostManifest;
        }
        finally {

        }
    }



    public HostManifest getQuoteInformationForHost(String hostname, TpmQuoteResponse tpmQuote) throws
             IOException, CertificateException {
        return getQuoteInformationForHost(hostname, tpmQuote, null);
    }

    // NOTE:  this v2 client method is a little different from the getQuoteInformationForHost for the v1 trust agent because
    //        it hashes the nonce and the ip address together  (instead of replacing the last 4 bytes of the nonce
    //        with the ip address like the v1 does)
    public HostManifest getQuoteInformationForHost(String hostname, TpmQuoteResponse tpmQuoteResponse, Nonce challenge) throws IOException, CertificateException {


            //  BUG #497  START CODE SNIPPET MOVED TO INTEL HOST AGENT
            byte[] nonce;
            if (challenge == null) {
                nonce = generateNonce(); // 20 random bytes
            } else {
                nonce = challenge.toByteArray(); // issue #4978: use specified nonce, if available
            }

            // to fix issue #1038 we have a new option to put the host ip address in the nonce (we don't send this to the host - the hsot automatically would do the same thing)
            byte[] verifyNonce = nonce; // verifyNonce is what we save to verify against host's tpm quote response
            if (quoteWithIPAddress) {
                // is the hostname a dns name or an ip address?  if it's a dns name we have to resolve it to an ip address
                // see also corresponding code in TrustAgent CreateNonceFileCmd
                byte[] ipaddress = getIPAddress(hostname);
                if (ipaddress == null) {
                    throw new IllegalArgumentException("mtwilson.tpm.quote.ipv4 is enabled but host address cannot be resolved: " + hostname);
                }
                verifyNonce = Sha1Digest.digestOf(nonce).extend(ipaddress).toByteArray();
            }
    //        String verifyNonceBase64 = Base64.encodeBase64String(verifyNonce);

            String sessionId = generateSessionId();

            // FIrst let us ensure that we have an AIK cert created on the host before trying to retrieve the quote. The trust agent
            // would verify if a AIK is already present or not. If not it will create a new one.
            //trustedAik = X509Util.encodePemCertificate(aik);
            trustedAik = X509Util.encodePemCertificate(tpmQuoteResponse.aik);

            // to fix issue #1038 trust agent relay we send 20 random bytes nonce to the host (base64-encoded) but if mtwilson.tpm.quote.ipaddress is enabled then in our copy we replace the last 4 bytes with the host's ip address, and when the host generates the quote it does the same thing, and we can verify it later
            // we select best PCR bank but we will change to all PCR banks once it's supported
            //tpmQuoteResponse = client.getTpmQuote(nonce, new int[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}, host.getPcrBanks()); // pcrList used to be a comma-separated list passed to this method... but now we are returning a quote with ALL the PCR's ALL THE TIME.
            log.debug("got response from server [" + hostname + "] ");

            log.debug("extracted quote from response: {}", Base64.encodeBase64String(tpmQuoteResponse.quote));

            // for Windows host, we generate a new nonce by sha1(nonce | tag)
            // Now is done for ALL hosts, not only Windows
            if (tpmQuoteResponse.isTagProvisioned) {
                log.debug("tpmQuoteResponse.isTagProvisioned is true");
                verifyNonce = Sha1Digest.digestOf(verifyNonce).extend(tpmQuoteResponse.assetTag).toByteArray();
            }

            RSAPublicKey rsaPublicKey = (RSAPublicKey) tpmQuoteResponse.aik.getPublicKey();


            // Verify if there is TCBMeasurement Data. This data would be available if we are extending the root of trust to applications and data on the OS
            List<String> tcbMeasurementStrings = tpmQuoteResponse.tcbMeasurements;
            logMeasurements(tcbMeasurementStrings);

            log.debug("Event log: {}", tpmQuoteResponse.eventLog); // issue #879
            byte[] eventLogBytes = Base64.decodeBase64(tpmQuoteResponse.eventLog);// issue #879
            log.debug("Decoded event log length: {}", eventLogBytes == null ? null : eventLogBytes.length);// issue #879
            PcrManifest pcrManifest;
            if (eventLogBytes != null) { // issue #879
                String decodedEventLog = new String(eventLogBytes);
                log.debug("Event log retrieved from the host consists of: " + decodedEventLog);

                // Since we need to add the event log details into the pcrManifest, we will pass in that information to the below function
                pcrManifest = verifyQuoteAndGetPcr(sessionId, decodedEventLog, verifyNonce, tpmQuoteResponse.quote, rsaPublicKey);
            } else {
                pcrManifest = verifyQuoteAndGetPcr(sessionId, null, verifyNonce, tpmQuoteResponse.quote, rsaPublicKey); // verify the quote but don't add any event log info to the PcrManifest. // issue #879
                log.debug("Got PCR map");
            }
	    HostManifest hostManifest = new HostManifest();
            if (tcbMeasurementStrings !=null && !tcbMeasurementStrings.isEmpty()) {
                hostManifest.setMeasurementXmls(tcbMeasurementStrings);
            }
            hostManifest.setProvisionedTag(tpmQuoteResponse.assetTag);
            hostManifest.setAikCertificate(tpmQuoteResponse.aik);
            hostManifest.setAssetTagDigest(tpmQuoteResponse.assetTag);
            hostManifest.setPcrManifest(pcrManifest);
            return hostManifest;


    }

    public String getHostAttestationReport(String hostName, PcrManifest pcrManifest, String vmmName) throws XMLStreamException {
        XMLOutputFactory xof = XMLOutputFactory.newInstance();
        XMLStreamWriter xtw;
        StringWriter sw = new StringWriter();

        xtw = xof.createXMLStreamWriter(sw);
        xtw.writeStartDocument();
        xtw.writeStartElement("Host_Attestation_Report");
        xtw.writeAttribute("Host_Name", hostName);
        xtw.writeAttribute("Host_VMM", vmmName);
        xtw.writeAttribute("TXT_Support", String.valueOf(true));

        // Note: Map should be insertion sorted by insertion order
        Map<DigestAlgorithm, List<Pcr>> pcrs = pcrManifest.getPcrsMap();
        for (Map.Entry<DigestAlgorithm, List<Pcr>> e : pcrs.entrySet()) {
            for (Pcr p : e.getValue()) {
                if (this.host != null && this.host.getTpmVersion().equals("2.0") && !this.isHostWindows && e.getKey().toString().equalsIgnoreCase("SHA1")) {
                    continue;
                }
                xtw.writeStartElement("PCRInfo");
                xtw.writeAttribute("ComponentName", p.getIndex().toString());
                xtw.writeAttribute("DigestValue", p.getValue().toString().toUpperCase());
                xtw.writeAttribute("DigestAlgorithm", e.getKey().toString());
            }
        }

        // Now we need to traverse through the PcrEventLogs and write that also into the Attestation Report.
        Map<DigestAlgorithm, List<PcrEventLog>> logs = pcrManifest.getPcrEventLogMap();
        for (Map.Entry<DigestAlgorithm, List<PcrEventLog>> e : logs.entrySet()) {
            for (PcrEventLog pel : e.getValue()) {
                List<Measurement> eventLogs = pel.getEventLog();
                for (Measurement m : eventLogs) {
                    xtw.writeStartElement("EventDetails");
                    xtw.writeAttribute("EventName", "OpenSource.EventName");
                    xtw.writeAttribute("ComponentName", m.getLabel());
                    xtw.writeAttribute("DigestValue", m.getValue().toString().toUpperCase());
                    xtw.writeAttribute("DigestAlgorithm", pel.getPcrBank().toString().toUpperCase());
                    xtw.writeAttribute("ExtendedToPCR", String.valueOf(pel.getPcrIndex()));
                    xtw.writeAttribute("PackageName", "");
                    xtw.writeAttribute("PackageVendor", "");
                    xtw.writeAttribute("PackageVersion", "");
                    if (ArrayUtils.contains(openSourceHostSpecificModules, m.getLabel())) {
                        // For Xen, these modules would be vmlinuz and initrd and for KVM it would just be initrd.
                        xtw.writeAttribute("UseHostSpecificDigest", "true");
                    } else {
                        xtw.writeAttribute("UseHostSpecificDigest", "false");
                    }
                    xtw.writeEndElement();
                }
            }
        }
        xtw.writeEndElement();
        xtw.writeEndDocument();
        xtw.flush();
        xtw.close();

        String attestationReport = sw.toString();
        return attestationReport;
    }

    public byte[] generateNonce() {
        // Create a secure random number generator
        SecureRandom sr = RandomUtil.getSecureRandom();
        // Get 1024 random bits
        byte[] bytes = new byte[20]; // bug #1038  nonce should be 20 random bytes;  even though we send 20 random bytes to the host, both we and the host will replace the last 4 bytes with the host's primary IP address
        sr.nextBytes(bytes);

        log.debug("Nonce Generated {}", Base64.encodeBase64String(bytes));
        return bytes;
    }

    private String generateSessionId() {

        // Create a secure random number generator
        SecureRandom sr = RandomUtil.getSecureRandom();
        // Get 1024 random bits
        byte[] seed = new byte[1];
        sr.nextBytes(seed);

        sr = RandomUtil.getSecureRandom();
        sr.setSeed(seed);

        int nextInt = sr.nextInt();
        String sessionId = "" + ((nextInt < 0) ? nextInt * -1 : nextInt);
        log.debug("Session Id Generated [{}]", sessionId);

        return sessionId;
    }

    private PcrManifest verifyQuoteAndGetPcr(String sessionId, String eventLog, byte[] challenge, byte[] quoteBytes, RSAPublicKey rsaPublicKey) {
        List<String> result = new ArrayList<>();
        PcrManifest pcrManifest = new PcrManifest();
        log.debug("verifyQuoteAndGetPcr for session {}", sessionId);

        Map<Integer, Map<String, String>> pcrMap = new LinkedHashMap<>();
        try {
            if (host.getTpmVersion().equals("2.0")) {
                result = Arrays.asList(new AikQuoteVerifier2().verifyAIKQuote(challenge, quoteBytes, rsaPublicKey).split("\n"));
            } else {
                if (isHostWindows) {
                    result = Arrays.asList(new AikQuoteVerifierWindows().verifyAIKQuoteWindows(challenge, quoteBytes, rsaPublicKey).split("\n"));
                } else {
                    result = Arrays.asList(new AikQuoteVerifier().verifyAIKQuote(challenge, quoteBytes, rsaPublicKey).split("\n"));
                }
            }
        } catch (Exception exc) {
            throw new IllegalStateException("Cannot verify AIK Quote", exc);
        }


        //List<String> result = CommandUtil.runCommand(command, true, "VerifyQuote");
        //log.debug("Verify quote command result: {}", StringUtils.join(result.iterator(), "\n"));
        // Sample output from command:
        //  1 3a3f780f11a4b49969fcaa80cd6e3957c33b2275
        //  17 bfc3ffd7940e9281a3ebfdfa4e0412869a3f55d8
        for (String pcrString : result) {
            String[] parts = pcrString.trim().split(" ");
            if (parts.length == 2) {
                /* parts[0] contains pcr index and the bank algorithm
                 * in case of SHA1, the bank algorithm is not attached. so the format is just the pcr number same as before
                 * in case of SHA256 or other algorithms, the format is "pcrNumber_SHA256"
                 */
                String[] pcrIndexParts = parts[0].trim().split("_");
                String pcrNumber = pcrIndexParts[0].trim().replaceAll(pcrNumberUntaint, "").replaceAll("\n", "");
                String pcrBank;
                if (pcrIndexParts.length == 2) {
                    pcrBank = pcrIndexParts[1].trim();
                } else {
                    pcrBank = "SHA1";
                }
                String pcrValue = parts[1].trim().replaceAll(pcrValueUntaint, "").replaceAll("\n", "");

                if(isHostWindows && pcrValue.length()==64)
                    pcrBank = "SHA256";


                boolean validPcrNumber = pcrNumberPattern.matcher(pcrNumber).matches();
                boolean validPcrValue = pcrValuePattern.matcher(pcrValue).matches();
                if (validPcrNumber && validPcrValue) {
                    log.debug("Result PCR " + pcrNumber + ": " + pcrValue);
                    // TODO: structure returned by this will be different, so we can actually select the algorithm by type and not length
                    if (pcrBank.equals("SHA256")) {
                        pcrManifest.setPcr(PcrFactory.newInstance(DigestAlgorithm.SHA256, PcrIndex.valueOf(pcrNumber), pcrValue));
                    } else if (pcrBank.equals("SHA1")) {
                        pcrManifest.setPcr(PcrFactory.newInstance(DigestAlgorithm.SHA1, PcrIndex.valueOf(pcrNumber), pcrValue));
                    }
                }
            } else {
                log.warn("Result PCR invalid");
            }
        }

        // Now that we captured the PCR details, we need to capture the module information also into the PcrManifest object
        // Sample Format:
        // <modules>
        //<module><pcrNumber>17</pcrNumber><name>tb_policy</name><value>9704353630674bfe21b86b64a7b0f99c297cf902</value></module>
        //<module><pcrNumber>18</pcrNumber><name>xen.gz</name><value>dfdffe5d3bdff697c4d7447115440e34fa27c1a4</value></module>
        //<module><pcrNumber>19</pcrNumber><name>vmlinuz</name><value>d3f525b0dc6f7d7c9a3af165bcf6c3e3e02b2599</value></module>
        //<module><pcrNumber>19</pcrNumber><name>initrd</name><value>3dfa5762c78623ccfc778498ab4cb7136bb3f5ab</value></module>
        //</modules>
        if (eventLog != null) { // issue #879
            try {
                XMLInputFactory xif = XMLInputFactory.newInstance();
                //FileInputStream fis = new FileInputStream("c:\\temp\\nbtest.txt");
                StringReader sr = new StringReader(eventLog);
                XMLStreamReader reader = xif.createXMLStreamReader(sr);

                int extendedToPCR = -1;
                String digestValue = "";
                String componentName = "";
                String pcrBank = "SHA1";

                while (reader.hasNext()) {
                    if (reader.getEventType() == XMLStreamConstants.START_ELEMENT
                            && reader.getLocalName().equalsIgnoreCase("module")) {
                        reader.next();

                        if (reader.getLocalName().equalsIgnoreCase("pcrBank")) {
                            pcrBank = reader.getElementText().toUpperCase();
                            reader.next();
                        }

                        // Get the PCR Number to which the module is extended to
                        if (reader.getLocalName().equalsIgnoreCase("pcrNumber")) {
                            extendedToPCR = Integer.parseInt(reader.getElementText());
                        }

                        reader.next();
                        // Get the Module name
                        if (reader.getLocalName().equalsIgnoreCase("name")) {
                            componentName = reader.getElementText();
                        }

                        reader.next();
                        // Get the Module hash value
                        if (reader.getLocalName().equalsIgnoreCase("value")) {
                            digestValue = reader.getElementText();
                        }

                        log.debug("Process module [" + componentName + "] getting extended to [" + extendedToPCR + "] has value: " + digestValue);

                        // Attach the PcrEvent logs to the corresponding pcr indexes.
                        // Note: Since we will not be processing the even logs for 17 & 18, we will ignore them for now.                        
                        Measurement m = convertHostTpmEventLogEntryToMeasurement(extendedToPCR, componentName, digestValue, pcrBank);
                        if (pcrManifest.containsPcrEventLog(pcrBank, PcrIndex.valueOf(extendedToPCR))) {
                            pcrManifest.getPcrEventLog(pcrBank, extendedToPCR).getEventLog().add(m);
                        } else {
                            ArrayList<Measurement> list = new ArrayList<Measurement>();
                            list.add(m);
                            pcrManifest.setPcrEventLog(PcrEventLogFactory.newInstance(pcrBank, PcrIndex.valueOf(extendedToPCR), list));
                        }
                    }
                    reader.next();
                }
            } catch (Exception ex) {
                // bug #2171 we need to throw an exception to prevent the host from being registered with an error manifest
                throw new IllegalStateException("Invalid measurement log", ex);
            }
        }

        return pcrManifest;

    }

    /**
     * Helper method to create the Measurement Object.
     *
     * @param extendedToPcr
     * @param moduleName
     * @param moduleHash
     * @return
     */
    private static Measurement convertHostTpmEventLogEntryToMeasurement(int extendedToPcr, String moduleName, String moduleHash, String pcrBank) {
        HashMap<String, String> info = new HashMap();
        info.put("EventName", "OpenSource.EventName");  // For OpenSource since we do not have any events associated, we are creating a dummy one.
        // Removing the prefix of "OpenSource" as it is being captured in the event type
        info.put("ComponentName", moduleName);

        DigestAlgorithm da = DigestAlgorithm.valueOf(pcrBank);
        switch (da) {
            case SHA1:
                return new MeasurementSha1(new Sha1Digest(moduleHash), moduleName, info);
            case SHA256:
                return new MeasurementSha256(new Sha256Digest(moduleHash), moduleName, info);
            default:
                throw new UnsupportedOperationException("PCRBank: " + pcrBank + " not supported");
        }
    }

    private void logMeasurements(List<String> tcbMeasurementStrings) {
        if(tcbMeasurementStrings != null) {
            log.debug("Received {} TCB Measurement XMLs", tcbMeasurementStrings.size());
            for (String measurement : tcbMeasurementStrings) {
                log.debug("TCB Measurement XML is {}", measurement);
            }
        }
    }
}
