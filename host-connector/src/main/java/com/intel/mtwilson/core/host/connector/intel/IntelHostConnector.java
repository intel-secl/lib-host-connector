/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.host.connector.intel;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.mtwilson.core.common.model.HostInfo;
import com.intel.mtwilson.core.host.connector.HostConnector;
import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.dcsg.cpg.net.InternetAddress;
import com.intel.mtwilson.core.common.model.Nonce;
import com.intel.mtwilson.core.common.model.PcrManifest;
import com.intel.mtwilson.core.common.trustagent.client.jaxrs.TrustAgentClient;
import com.intel.mtwilson.core.common.trustagent.model.TpmQuoteResponse;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.commons.codec.binary.Base64;

/**
 * Instances of VmwareAgent should be created by the VmwareAgentFactory
 * 
 * @author zaaquino
 */
public class IntelHostConnector implements HostConnector {
    private static final transient org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(IntelHostConnector.class);
    private transient final TrustAgentClient client;
    private final InternetAddress hostAddress;
    private String vendorHostReport = null;
    private String vmmName = null;
    private HostManifest hostManifest = null;

    public IntelHostConnector(TrustAgentClient client, InternetAddress hostAddress) throws Exception {
        this.client = client;
        this.hostAddress = hostAddress;
    }
    
    
    @Override
    public boolean isTpmPresent() {
        // bug #538  for now assuming all trust-agent hosts have tpm since we don't have a separate capabilities call
        return true; 
    }
    
    @Override
    public PublicKey getAik() {
        X509Certificate aikcert = getAikCertificate();
        return aikcert.getPublicKey();
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

    @Override
    public HostManifest getHostManifest() throws IOException {
        if( hostManifest == null ) {
            try {
                TAHelper helper = new TAHelper(getHostDetails());
                hostManifest = helper.getQuoteInformationForHost(hostAddress.toString(), client, null);
                hostManifest.setHostInfo(getHostDetails());
            } catch(IOException | CertificateException e) {
                throw new IOException(String.format("Cannot retrieve PCR manifest from %s", hostAddress.toString()), e);
            }
        }
        return hostManifest;
    }
    
    @Override
    public HostManifest getHostManifest(TpmQuoteResponse tpmQuote, HostInfo hostInfo, Nonce challenge) throws IOException {
        HostManifest manifest = new HostManifest();
        manifest.setHostInfo(hostInfo);
        manifest.setPcrManifest(getPcrManifest(tpmQuote, hostInfo, tpmQuote.aik, challenge));
        manifest.setAssetTagDigest(manifest.getPcrManifest().getProvisionedTag());
        manifest.setAikCertificate(tpmQuote.aik);
        return manifest;
    }
    
    @Override
    public boolean isIntelTxtSupported() {
        return true; 
    }
    
    @Override
    public boolean isIntelTxtEnabled() {
        return true;
    }

    @Override
    public boolean isTpmEnabled() {
        return true;
    }

    @Override
    public boolean isEkAvailable() {
        return false; // vmware does not make the EK available through its API
    }

    @Override
    public boolean isAikAvailable() {
        return true;  // assume we can always get an AIK from a trust agent,  for now
    }

    @Override
    public boolean isAikCaAvailable() {
        return true; // assume hosts running trust agent always use a privacy ca,  for now
    }

    @Override
    public boolean isDaaAvailable() {
        return false; // intel trust agent currently does not support DAA
    }
    
    @Override
    public X509Certificate getEkCertificate() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public String getHostAttestationReport(String pcrList) throws IOException {
        return getHostAttestationReport(pcrList, null);
    }

    @Override
    public String getHostAttestationReport(String pcrList, Nonce challenge) throws IOException {
        if( vendorHostReport != null ) { return vendorHostReport; }
        if( vmmName == null ) { getHostDetails(); }
        try {
            TAHelper helper = new TAHelper(getHostDetails());           
            // currently the getHostAttestationReport function is ONLY called from Management Service HostBO.configureWhiteListFromCustomData(...)  so there wouldn't be any saved trusted AIK in the database anyway
            HostManifest manifest = helper.getQuoteInformationForHost(hostAddress.toString(), client, challenge);
            vendorHostReport = helper.getHostAttestationReport(hostAddress.toString(), manifest.getPcrManifest(), vmmName);
            log.debug("Host attestation report for {}", hostAddress);
            log.debug(vendorHostReport);
            return vendorHostReport;
        } catch(IOException | CertificateException | XMLStreamException e) {
            throw new IOException(e);
        }
    }
    
    @Override
    public X509Certificate getAikCertificate() {
        try {
            X509Certificate aik = client.getAik();
            return aik;
        } catch(Exception e) {
            log.debug("Cannot retrieve AIK certificate: {}", e.toString(), e);
            return null;
        }
    }
    
    @Override
    public X509Certificate getAikCaCertificate() {
        try {
            X509Certificate privacyCA = client.getAikCa();
            return privacyCA;
        } catch(Exception e) {
            log.debug("Cannot retrieve Privacy CA certificate: {}", e.toString(), e);
            throw e;
        }
    }
    
    @Override
    public X509Certificate getBindingKeyCertificate() {
        try {
            X509Certificate bindingKeyCert = client.getBindingKeyCertificate();
            return bindingKeyCert;
        } catch(Exception e) {
            log.warn("Cannot retrieve Binding key certificate: {}", e.toString(), e);
            return null;
        }
    }
    
     @Override
    public HostInfo getHostDetails() throws IOException {
        HostInfo hostInfo = client.getHostInfo();
        hostInfo.setBiosName(hostInfo.getBiosName());
        hostInfo.setOsName(hostInfo.getOsName());
        hostInfo.setHardwareUuid(hostInfo.getHardwareUuid().toUpperCase()); //convert it to uppercase for consistency
        vmmName = hostInfo.getVmmName().trim();
        return hostInfo;
    }
    
     @Override
    public boolean setAssetTagSha256(com.intel.dcsg.cpg.crypto.Sha256Digest tag) throws IOException {
        Map<String, String> hm = getHostAttributes();
        log.debug("calling trustAgentClient with {} | {}", tag.toHexString(), hm.get("Host_UUID"));
        client.writeTag(tag.toByteArray(), UUID.valueOf(hm.get("Host_UUID")));
        return true;
    }
    
     @Override
    public Map<String, String> getHostAttributes() throws IOException {
       HashMap<String,String> hm = new HashMap();
        // Retrieve the data from the host and add it into the hashmap
        HostInfo hostInfo = client.getHostInfo();
        // Currently we are just adding the UUID of th host. Going ahead we can add additional details
        if (hostInfo != null)
            hm.put("Host_UUID", hostInfo.getHardwareUuid().trim());

        return hm;
    }
    
    @Override
    public PcrManifest getPcrManifest() throws IOException {
        return getPcrManifest(null);
    }
    
    /**
     *
     * @param challenge optional; may be null
     * @return PcrManifest java model object.
     * @throws IOException This method throws IOException.
     */
    @Override
    public PcrManifest getPcrManifest(Nonce challenge) throws IOException {
        if( hostManifest == null ) {
            try {
                TAHelper helper = new TAHelper(getHostDetails());
                hostManifest = helper.getQuoteInformationForHost(hostAddress.toString(), client, challenge);
            } catch(IOException | CertificateException  e) {
                throw new IOException(String.format("Cannot retrieve PCR manifest from %s", hostAddress.toString()), e);
            }
        }
        return hostManifest.getPcrManifest();
    }
    
    @Override
    public PcrManifest getPcrManifest(TpmQuoteResponse tpmQuote, HostInfo hostInfo, X509Certificate aik, Nonce challenge) throws IOException {
        if( hostManifest == null ) {
            try {
                TAHelper helper = new TAHelper(hostInfo);
                hostManifest = helper.getQuoteInformationForHost(hostAddress.toString(), tpmQuote, challenge);
            }
            catch(IOException | CertificateException e) {
                throw new IOException(String.format("Cannot retrieve PCR manifest from %s", hostAddress.toString()), e);
            }
        }
        return hostManifest.getPcrManifest();
    }
    
    @Override
    public TpmQuoteResponse getTpmQuoteResponse(Nonce challenge) throws IOException{
           TpmQuoteResponse quoteResponse;
           try {
               quoteResponse = client.getTpmQuote(challenge.toByteArray(), new int[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}, getHostDetails().getPcrBanks());
            } catch(Exception e) {
                throw new IOException("Cannot retrieve TPM quote response", e);
            }
        return quoteResponse;
    }
}
