/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.host.connector.vmware;

import com.intel.dcsg.cpg.crypto.digest.Digest;
import com.intel.mtwilson.core.common.datatypes.ConnectionString;
import com.intel.mtwilson.core.host.connector.VendorHostConnectorFactory;
import com.intel.dcsg.cpg.net.InternetAddress;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
import com.intel.mtwilson.core.common.datatypes.Vendor;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.RemoteException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The VmwareHostConnectorFactory creates instances of VmwareHostConnector. It does
 * not create instances of VmwareClient. It uses 
 * @author jbuhacoff
 */
public class VmwareHostConnectorFactory implements VendorHostConnectorFactory {
    private Logger log = LoggerFactory.getLogger(getClass());
    private String vmwareVendorConnectionString = "";
    protected static VMwareConnectionPool pool = new VMwareConnectionPool(new VmwareClientFactory()); 
    
    @Override
    public String getVendorProtocol() { return "vmware"; }
    
    
    @Override
    public VmwareHostConnector getHostConnector(InternetAddress hostAddress, String vendorConnectionString, TlsPolicy tlsPolicy) throws IOException {
        try {
            vmwareVendorConnectionString = new ConnectionString(Vendor.VMWARE, vendorConnectionString).getConnectionStringWithPrefix();
            // If the connection string does not include the host address, add it here so that if there is an exception in the client layer the hostname will appear when printing the connection string
            ConnectionString.VmwareConnectionString connStr = ConnectionString.VmwareConnectionString.forURL(vendorConnectionString);
            if( connStr.getHost() == null ) {
                connStr.setHost(hostAddress);
                vendorConnectionString = connStr.toString();
            }
            // Original call 
          URL url = new URL(vendorConnectionString);
          
            VMwareClient client = pool.getClientForConnection(new TlsConnection(url, tlsPolicy));
//            VMwareClient client = pool.createClientForConnection(new TlsConnection(vendorConnectionString, tlsPolicy));
            return new VmwareHostConnector(client, connStr.getHost().toString());
        }
        catch(Exception e) {
            throw new IOException("Cannot get vmware client for host: "+hostAddress.toString()+": "+e.toString(), e);
        }
    }

    @Override
    public VmwareHostConnector getHostConnector(String vendorConnectionString, TlsPolicy tlsPolicy) throws IOException {
        ConnectionString.VmwareConnectionString vmware = ConnectionString.VmwareConnectionString.forURL(vendorConnectionString);
        try {
            vmwareVendorConnectionString = vendorConnectionString;
            URL url = new URL(vendorConnectionString);
            VMwareClient client = createClientForConnection(new TlsConnection(url, tlsPolicy));
            log.debug("vmware host = {}", vmware.getHost().toString());
            log.debug("vmware port = {}", vmware.getPort());
            log.debug("vmware vcenter = {}", vmware.getVCenter().toString());
            return new VmwareHostConnector(client, vmware.getHost().toString());
        } catch (MalformedURLException | VMwareConnectionException | RemoteException e) {
            throw new IOException(String.format("Cannot get vmware client for host [%s] at vcenter [%s] with username [%s]: %s",
                    vmware.getHost().toString(), vmware.getVCenter().toString(), vmware.getUsername(), e.toString()), e);
        }
    }
    
    @Override
    public String getVendorConnectionString() {
        return vmwareVendorConnectionString;
    }
    
    public VMwareClient createClientForConnection(TlsConnection tlsConnection) throws VMwareConnectionException {
        try {
            VmwareClientFactory vmwareClientFactory = new VmwareClientFactory();
            VMwareClient client = vmwareClientFactory.makeObject(tlsConnection);
            if (!vmwareClientFactory.validateObject(tlsConnection, client)) {
                throw new VMwareConnectionException("Failed to validate new vmware connection");
            }
            return client;
        } catch(javax.xml.ws.WebServiceException e) {
            // is it because of an ssl failure?  we're looking for this:  com.sun.xml.internal.ws.client.ClientTransportException: HTTP transport error: javax.net.ssl.SSLHandshakeException: java.security.cert.CertificateException: Server certificate is not trusted
            if( e.getCause() != null && e.getCause() instanceof javax.net.ssl.SSLHandshakeException) {
                javax.net.ssl.SSLHandshakeException e2 = (javax.net.ssl.SSLHandshakeException)e.getCause();
                if( e2.getCause() != null && e2.getCause() instanceof com.intel.dcsg.cpg.tls.policy.UnknownCertificateException ) {
                    com.intel.dcsg.cpg.tls.policy.UnknownCertificateException e3 = (com.intel.dcsg.cpg.tls.policy.UnknownCertificateException)e2.getCause();
                    log.warn("Failed to connect to vcenter due to unknown certificate exception: {}", e3.toString());
                    X509Certificate[] chain = e3.getCertificateChain();
                    if( chain == null || chain.length == 0 ) {
                        log.error("Server certificate is missing");
                    }
                    else {
                        for(X509Certificate certificate : chain) {
                            try {
                                log.debug("Server certificate SHA-256 fingerprint: {} and subject: {}", Digest.sha256().digest(certificate.getEncoded()).toHex(), certificate.getSubjectX500Principal().getName());
                            }
                            catch(CertificateEncodingException e4) {
                                log.error("Cannot read server certificate: {}", e4.toString(), e4);
                                throw new VMwareConnectionException(e4);
                            }
                        }
                        throw new VMwareConnectionException("VMwareConnectionPool not able to read host information: "+ e3.toString());
                    }
                } else {
                    throw new VMwareConnectionException("Failed to connect to vcenter due to SSL handshake exception", e2);
                }
            } else {
                throw new VMwareConnectionException("Failed to connect to vcenter due to exception: "+e.toString(), e);
            }
        } catch(KeyManagementException | NoSuchAlgorithmException | IOException | VMwareConnectionException e) {
            log.error("Failed to connect to vcenter: {}", e.toString(), e);
            throw new VMwareConnectionException(String.format("Cannot connect to vcenter: %s", tlsConnection.getURL().getHost()), e);
        }
        throw new VMwareConnectionException("Failed to connect to vcenter: unknown error");
    }
}
