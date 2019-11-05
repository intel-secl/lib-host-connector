/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.host.connector.integration;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.Sha384Digest;
import com.intel.dcsg.cpg.extensions.WhiteboardExtensionProvider;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
import com.intel.dcsg.cpg.tls.policy.impl.InsecureTlsPolicy;

import com.intel.kunit.annotations.*;

import com.intel.mtwilson.core.host.connector.*;
import com.intel.mtwilson.core.host.connector.intel.IntelHostConnectorFactory;
import com.intel.mtwilson.core.common.model.Nonce;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import com.intel.mtwilson.core.host.connector.intel.MicrosoftHostConnectorFactory;
import com.intel.mtwilson.core.host.connector.vmware.VmwareHostConnectorFactory;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider; 
import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.mtwilson.core.common.model.PcrManifest;
import com.intel.mtwilson.core.common.model.HostInfo;
import com.intel.mtwilson.core.common.trustagent.model.TpmQuoteResponse;

import java.io.IOException;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;


/**
 * Integration Test for Host Connector Library 
 * 
 * @author zaaquino
 * @author dtiwari
 */
public class HostConnectorIntegration {
    final TlsPolicy tlsPolicy = new InsecureTlsPolicy();
    HostConnectorFactory factory = new HostConnectorFactory();
    String apiName;
    
    @BeforeAll
    public static void setup() throws IOException {
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, IntelHostConnectorFactory.class);
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, MicrosoftHostConnectorFactory.class);
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, VmwareHostConnectorFactory.class);
    }
    
    @Integration
    public void testGetHostManifestFromLib(String hostConn, String aasApiUrl) throws IOException, NoSuchAlgorithmException {
        apiName = "HostManifest getHostManifest(TpmQuoteResponse tpmQuote, HostInfo hostInfo, X509Certificate aik, Nonce challenge)throws IOException";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);

        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
        
        Nonce nonce = generateNonce();
        TpmQuoteResponse tpmQuoteResponse = hostConnector.getTpmQuoteResponse(nonce);
        HostInfo hostinfo = hostConnector.getHostDetails();

        HostManifest hostManifest = hostConnector.getHostManifest(tpmQuoteResponse,
                                                                  hostinfo,
                                                                  nonce);
        X509Certificate aikCertificate = hostManifest.getAikCertificate();
        String hostManifestInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(hostManifest);
        
        
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n Generated TpmQuoteResponse tpmQuote \n" + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(tpmQuoteResponse));
        System.out.println("\n Generated HostInfo hostInfo \n" + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(hostinfo));
        System.out.println("\n Generated X509Certificate aik \n" + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(aikCertificate));
        System.out.println("\n Generated Nonce nonce (in BASE64 byte array) \n" + Base64.encodeBase64String(nonce.toByteArray()));
        
        System.out.println("\n RESULT: Host Manifest for Host with Connection string " + hostConn);
        System.out.println(hostManifestInString); 
    }
    
    @Integration
    public void testGetHostManifest(String hostConn, String aasApiUrl) throws IOException, NoSuchAlgorithmException {
        apiName = "HostManifest getHostManifest()throws IOException";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
        
        HostManifest hostManifest = hostConnector.getHostManifest();
        String hostManifestInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(hostManifest);
        
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: Host Manifest for Host with Connection string " + hostConn);
        System.out.println(hostManifestInString); 
    }
    
    @Integration
    public void testGetHostInfo(String hostConn, String aasApiUrl) throws IOException, NoSuchAlgorithmException {
        apiName = "HostInfo getHostDetails() throws IOException";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
        
        HostInfo hostInfo = hostConnector.getHostDetails();
        String hostInfoInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(hostInfo);
        
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: Host Info for Host with Connection string " + hostConn);
        System.out.println(hostInfoInString); 
    }
    
    
    @Integration
    public void testGetHostAttestationReport(String hostConn, String aasApiUrl) throws IOException, NoSuchAlgorithmException {
        apiName = "String getHostAttestationReport(String pcrList) throws IOException";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
        
        String hostAttestationReport = hostConnector.getHostAttestationReport(""); // Note : BUG
        
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: Host Attestation Report for Host with Connection string " + hostConn);
        System.out.println(hostAttestationReport); 
    }
    
    
    @Integration
    public void testGetHostAttestationReportWithNonce(String hostConn, String aasApiUrl) throws IOException, NoSuchAlgorithmException {
        apiName = "String getHostAttestationReport(String pcrList, Nonce challenge) throws IOException";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
        
        Nonce nonce = generateNonce();
        String hostAttestationReport = hostConnector.getHostAttestationReport("", nonce); // Note : BUG
        
        
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n Generated Nonce nonce (in BASE64 byte array) \n" + Base64.encodeBase64String(nonce.toByteArray()));
        System.out.println("\n RESULT: Host Attestation Report for Host with Connection string " + hostConn);
        System.out.println(hostAttestationReport); 
    }
    
    @Integration
    public void testGetHostAttributes(String hostConn, String aasApiUrl) throws IOException{
        apiName = "Map<String,String> getHostAttributes() throws IOException";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
   
        Map<String,String> hostAttributes = hostConnector.getHostAttributes();
        
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: Host Attributes for Host with Connection string " + hostConn);
        System.out.println(hostAttributes); 
    }

    @Integration
    public void testSetAssetTagSha384(String hostConn, String aasApiUrl, String sha384Digest) throws IOException, NoSuchAlgorithmException {
        apiName = "boolean setAssetTagSha384(Sha384Digest tag) throws IOException";
        Sha384Digest certSha384 = Sha384Digest.valueOf(sha384Digest);
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        boolean aTagSet = hostConnector.setAssetTagSha384(certSha384);
        
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        if (aTagSet){
            System.out.println("\n RESULT: Asset Tag Set successful for Host with Connection String " + hostConn);
        }
        else{
            System.out.println("\n RESULT: Asset Tag Set unsuccessful for Host with Connection String " + hostConn);
        }
    }
    
    @Integration
    public void testgetAikCertificate(String hostConn, String aasApiUrl) throws IOException, NoSuchAlgorithmException {
        apiName = "X509Certificate getAikCertificate()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        X509Certificate aikCaCertificate = hostConnector.getAikCertificate();
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper(); 
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
        String aikCertificateInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(aikCaCertificate);
        
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: AIK CA Certificate for Host with Connection string " + hostConn);
        System.out.println(aikCertificateInString);
    }
    
    @Integration
    public void testgetAik(String hostConn, String aasApiUrl) throws IOException, NoSuchAlgorithmException {
        apiName = "PublicKey getAik()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        PublicKey aik = hostConnector.getAik();
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper(); 
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
        String aikInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(aik);
        
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: AIK Public Key for Host with Connection string " + hostConn);
        System.out.println(aikInString);
    }
    
    @Integration
    public void testgetAikCaCertificate(String hostConn, String aasApiUrl) throws IOException, NoSuchAlgorithmException {
        apiName = "X509Certificate getAikCaCertificate()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        X509Certificate aikCaCertificate = hostConnector.getAikCaCertificate();
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper(); 
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
        String aikCertificateInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(aikCaCertificate);
        
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: AIK CA Certificate for Host with Connection string " + hostConn);
        System.out.println(aikCertificateInString);
    }

    @Integration
    public void testgetBindingKeyCertificate(String hostConn, String aasApiUrl) throws IOException, NoSuchAlgorithmException {
        // Currently Binding Key Certificate is not supported in Phase 1
        apiName = "X509Certificate getBindingKeyCertificate()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: Binding Key Certificate for Host with Connection string " + hostConn);
        System.out.println(hostConnector.getBindingKeyCertificate().getSigAlgName()); 
    }
    
    
    @Integration
    public void testGetPcrManifest(String hostConn, String aasApiUrl) throws IOException {
       apiName = "PcrManifest getPcrManifest() throws IOException";
       HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
       
       PcrManifest pcrManifest = hostConnector.getPcrManifest();
       ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper(); 
       mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
       String pcrManifestInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(pcrManifest);
       
       System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
       System.out.println("\n RESULT: PCR Manifest with Nonce for Host with Connection string " + hostConn);
       System.out.println(pcrManifestInString);  
    }
    
    @Integration
    public void testGetPcrManifestwithNonce(String hostConn, String aasApiUrl) throws IOException {
       apiName = "PcrManifest getPcrManifest(Nonce challenge) throws IOException";
       HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
       
       Nonce nonce = generateNonce();
       PcrManifest pcrManifest = hostConnector.getPcrManifest(nonce);
       ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper(); 
       mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
       String pcrManifestInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(pcrManifest);
       
       System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
       System.out.println("\n Generated Nonce nonce (in BASE64 byte array) \n" + Base64.encodeBase64String(nonce.toByteArray()));
       
       System.out.println("\n RESULT:PCR Manifest with Nonce for Host with Connection string " + hostConn);
       System.out.println(pcrManifestInString);  
    }
    
    @Integration
    public void testGetPcrManifestwithAll(String hostConn, String aasApiUrl) throws IOException {
       apiName = "PcrManifest getPcrManifest(TpmQuoteResponse tpmQuote, HostInfo hostInfo, X509Certificate aik, Nonce challenge)  throws IOException";
       HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
       
       Nonce nonce = generateNonce();
       TpmQuoteResponse tpmQuoteResponse = hostConnector.getTpmQuoteResponse(nonce);
       HostInfo hostinfo = hostConnector.getHostDetails();
       X509Certificate aikCertificate = hostConnector.getAikCertificate();
        
       PcrManifest pcrManifest = hostConnector.getPcrManifest(tpmQuoteResponse,
                                                              hostinfo,
                                                              aikCertificate,
                                                              nonce);
       ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper(); 
       mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
       String pcrManifestInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(pcrManifest);
       
       System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
       System.out.println("\n Generated TpmQuoteResponse tpmQuote \n" + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(tpmQuoteResponse));
       System.out.println("\n Generated HostInfo hostInfo \n" + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(hostinfo));
       System.out.println("\n Generated X509Certificate aik \n" + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(aikCertificate));
       System.out.println("\n Generated Nonce nonce (in BASE64 byte array) \n" + Base64.encodeBase64String(nonce.toByteArray()));
       
       System.out.println("\n RESULT: PCR Manifest with Nonce for Host with Connection string " + hostConn);
       System.out.println(pcrManifestInString);  
    }
    
    @Integration
    public void testGetTpmQuoteResponse(String hostConn, String aasApiUrl) throws IOException {
       apiName = "TpmQuoteResponse getTpmQuoteResponse(Nonce challenge) throws IOException";
       HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
       
       Nonce nonce = generateNonce();
       TpmQuoteResponse tpmQuoteResponse = hostConnector.getTpmQuoteResponse(nonce);
       ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper(); 
       mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false); 
       String tpmQuoteResponseInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(tpmQuoteResponse);
       
       System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
       System.out.println("\n Generated Nonce nonce (in BASE64 byte array) \n" + Base64.encodeBase64String(nonce.toByteArray()));
       
       System.out.println("\n RESULT: TPM Quote with Nonce for Host with Connection string " + hostConn);
       System.out.println(tpmQuoteResponseInString);  
    }
    
    @Integration
    public void testIsDaaAvailable(String hostConn, String aasApiUrl){
        apiName = "boolean isDaaAvailable()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        boolean isAvailable = hostConnector.isDaaAvailable();
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: DAA Availabality for Host with Connection string " + hostConn);
        System.out.println(isAvailable);
    }
    
    @Integration
    public void testIsEkAvailable(String hostConn, String aasApiUrl){
        apiName = "boolean isEkAvailable()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        boolean isAvailable = hostConnector.isEkAvailable();
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: EK Availabality for Host with Connection string " + hostConn);
        System.out.println(isAvailable);
    }
    
    @Integration
    public void testIsAikAvailable(String hostConn, String aasApiUrl){
        apiName = "boolean isAikAvailable()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        boolean isAvailable = hostConnector.isAikAvailable();
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: Aik Availabality for Host with Connection string " + hostConn);
        System.out.println(isAvailable);
    }
    
    @Integration
    public void testIsAikCaAvailable(String hostConn, String aasApiUrl){
        apiName = "boolean isAikCaAvailable()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        boolean isAvailable = hostConnector.isAikCaAvailable();
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: AikCa Availabality for Host with Connection string " + hostConn);
        System.out.println(isAvailable);
    }
    
    @Integration
    public void testEkAvailable(String hostConn, String aasApiUrl){
        apiName = "boolean isEkAvailable()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        boolean isAvailable = hostConnector.isEkAvailable();
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: EK Availabality for Host with Connection string " + hostConn);
        System.out.println(isAvailable);
    }
    
    @Integration
    public void testIsIntelTxtSupported(String hostConn, String aasApiUrl){
        apiName = "boolean isIntelTxtSupported()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        boolean isSupported = hostConnector.isIntelTxtSupported();
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: Txt Supported for Host with Connection string " + hostConn);
        System.out.println(isSupported);
    }
    
    @Integration
    public void testIsIntelTxtEnabled(String hostConn, String aasApiUrl){
        apiName = "boolean isIntelTxtEnabled()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        boolean isEnabled = hostConnector.isIntelTxtEnabled();
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: Txt Enabled for Host with Connection string " + hostConn);
        System.out.println(isEnabled);
    }
    
    @Integration
    public void testIsTpmPresent(String hostConn, String aasApiUrl){
        apiName = "boolean isTpmPresent()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        boolean isPresent = hostConnector.isTpmPresent();
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: TPM Present for Host with Connection string " + hostConn);
        System.out.println(isPresent);
    }
    
    @Integration
    public void testIsTpmEnabled(String hostConn, String aasApiUrl){
        apiName = "boolean isTpmEnabled()";
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        
        boolean isEnabled = hostConnector.isTpmEnabled();
        System.out.println("\n\n=======================\n" + "API : " + apiName + "\n=======================\n");
        System.out.println("\n RESULT: TPM Enabled for Host with Connection string " + hostConn);
        System.out.println(isEnabled);
    } 
    
    private Nonce generateNonce(){
        SecureRandom sr = RandomUtil.getSecureRandom();
        byte[] bytes = new byte[20]; 
        sr.nextBytes(bytes);
        return new Nonce(bytes);
    } 
    
}
