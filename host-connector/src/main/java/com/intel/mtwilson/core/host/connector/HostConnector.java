/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.host.connector;

import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.mtwilson.core.common.model.Nonce;
import com.intel.mtwilson.core.common.model.HostInfo;
import com.intel.mtwilson.core.common.model.PcrManifest;
import com.intel.mtwilson.core.common.trustagent.model.TpmQuoteResponse;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;


/**
 *
 * @author zaaquino
 */
public interface HostConnector {
    
    /**
     * 
     * @return HostManifest java model object.
     * @throws IOException - This method throws an IOException.
     */
    HostManifest getHostManifest()throws IOException;
    
    HostManifest getHostManifest(TpmQuoteResponse tpmQuote, HostInfo hostInfo, Nonce challenge) throws IOException;
    /**
     * @return true if the host has a TPM
     */
    boolean isTpmPresent();
    
    boolean setAssetTagSha256(Sha256Digest tag) throws IOException;
    
    
    /**
     * Retrieve AIK (RSA public keys), the certificates only exist when a Privacy CA signs the public key to create a certificate.
     * 
     * @return Public key in PublicKey format.
     */
    PublicKey getAik();
    
    
    /**
     * Draft - maybe it should return an X509Certificate object
     * @return X509Certificate
     */
    X509Certificate getAikCertificate();
    
    X509Certificate getBindingKeyCertificate();   
    
    X509Certificate getEkCertificate();
    
    
    /**
     * Another adapter for existing code.  Each vendor returns a string in their own format.
     * @param pcrList  may be ignored, and the full list returned
     * @return String
     * @throws IOException - This method throws an IOException.
     */
    String getHostAttestationReport(String pcrList) throws IOException;

    String getHostAttestationReport(String pcrList, Nonce challenge) throws IOException;
    
    /**
     * Use this to obtain host-specific information such as UUID, which may be 
     * needed for dynamic whitelist rules.  Attributes returned with this method
     * may be referenced by name from dynamic whitelist rules.
     * @return Map String,String
     * @throws IOException - This method throws an IOException.
     * 
     * Sample Output 
     * ?xml version='1.0' encoding='UTF-8'?
     * Host_Attestation_Report Host_Name="192.168.0.1" vCenterVersion="5.0" HostVersion="5.0"
     *      PCRInfo ComponentName="0" DigestValue="1d670f2ae1dde52109b33a1f14c03e079ade7fea"
     *      PCRInfo ComponentName="17" DigestValue="ca21b877fa54dff86ed5170bf4dd6536cfe47e4d"
     *      PCRInfo ComponentName="18" DigestValue="8cbd66606433c8b860de392efb30d76990a3b1ed"
     * Host_Attestation_Report
     * 
     */
    Map<String,String> getHostAttributes() throws IOException;
    
      
    /**
     * @return HostInfo java model class object.
     * @throws IOException - This method throws an IOException.
     * SAMPLE OUTPUT FROM VMWare Host:
     * BIOS - OEM:Intel Corporation
     * BIOS - Version:S5500.86B.01.00.0060.090920111354
     * OS Name:VMware ESXi
     * OS Version:5.1.0
     * VMM Name: VMware ESXi
     * VMM Version:5.1.0-613838 (Build Number)
     * 
     */
    HostInfo getHostDetails() throws IOException; // original interface passed TxtHostRecord even though all the method REALLY needs is the connection string (hostname and url for vcenter,  ip adderss and port for intel but can be in the form of a connection string);  but since the hostagent interface is for a host already selected... we don't need any arguments here!!    the IOException is to wrap any client-specific error, could be changed to be soemthing more specific to trust utils library 
    
    
    
    /**
     * 
     * Agents should return the entire set of PCRs from the host. The attestation
     * service will then choose the ones it wants to verify against the whitelist.
     * Returning all PCR's is cheap (there are only 24) and makes the API simple.
     * 
     * Agents should return the entire set of module measurements from the host.
     * The attestation service will then choose what to verify and how. 
     * 
     * Bug #607 changed return type to PcrManifest and removed post-processing argument - 
     * each host agent implementation is reponsible for completing all its processing.
     * @return PcrManifest
     */

    /**
     * Retrieves entire set of PCRs from the host
     * 
     * @return PcrManifest represents a list of PCR numbers, their values, and any event
     * information that is available about each PCR that is reported from a specific host
     * 
     * @throws IOException - This method throws an IOException.
     */
    PcrManifest getPcrManifest() throws IOException;
    
    /**
     * 
     * @param challenge The challenge is a nonce value. 
     * @return PcrManifest Returns PCRManifest of the host. 
     * @throws IOException - This method throws an IOException.
     */
    PcrManifest getPcrManifest(Nonce challenge) throws IOException;
    
    /**
     * 
     * @param tpmQuote TpmQuoteResponse java model object.
     * @param hostInfo HostInfo java model object.
     * @param aik AIK certificate
     * @param challenge Nonce challenge.
     * @return PcrManifest Returns PCRManifest of the host.
     * @throws IOException - This method throws an IOException.
     */
    PcrManifest getPcrManifest(TpmQuoteResponse tpmQuote, HostInfo hostInfo, X509Certificate aik, Nonce challenge)  throws IOException;
    
    /**
     * Whether Intel TXT  has been enabled on the platform (usually through the BIOS)
     * @return True if TXT is enabled.
     */
    boolean isIntelTxtEnabled();
        
    boolean isTpmEnabled();

     /**
     * Linux and Citrix agents should return true, Vmware should return false.
     * @return true if we can obtain the EK for the host
     */
    boolean isEkAvailable();
    
    /**
     * Linux and Citrix agents should return true, Vmware should return false.
     * @return true if we can obtain am AIK for the host.
     */
    boolean isAikAvailable();
    
    /**
     * Linux agent should return true because we use the Privacy CA.
     * Citrix agent uses DAA so it should return false.
     * Vmware agent should return false.
     * @return true if AIk for a host is available.
     */
    boolean isAikCaAvailable();
    
    
    /**
     * Linux and Vmware agent should return false.
     * Citrix agent should return true.
     * @return true if the host supports Direct Anonymous Attestation
     */
    boolean isDaaAvailable();
    
    /**
     * Draft - maybe it should return an X509Certificate object
     * @return the Privacy CA certificate that is mentioned in the AIK Certificate
     */
    X509Certificate getAikCaCertificate(); 
    
    
    /**
     * Whether the platform supports Intel TXT - is the right hardware present (not including the TPM)
     * @return true if TXT is present on the host
     */
    boolean isIntelTxtSupported();
    
    TpmQuoteResponse getTpmQuoteResponse(Nonce challenge) throws IOException;
}
