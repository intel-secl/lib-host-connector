/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.host.connector.intel;

import com.intel.mtwilson.core.host.connector.VendorHostConnectorFactory;
import com.intel.mtwilson.core.host.connector.HostConnector;
import com.intel.mtwilson.core.common.datatypes.ConnectionString;
//import com.intel.mtwilson.My;
import com.intel.dcsg.cpg.net.InternetAddress;
import com.intel.mtwilson.core.common.datatypes.Vendor;
import com.intel.mtwilson.core.common.trustagent.client.jaxrs.TrustAgentClient;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;

import java.io.IOException;
import java.net.URL;
import java.util.Properties;
import javax.ws.rs.core.UriBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The IntelHostConnectorFactory creates instances of IntelHostConnector. It does
 * not create instances of IntelClient. It uses the IntelClientFactory to do that.
 * @author zaaquino
 */
public class IntelHostConnectorFactory implements VendorHostConnectorFactory {
    private Logger log = LoggerFactory.getLogger(getClass());
    private String intelVendorConnectionString = "";
    
    @Override
    public String getVendorProtocol() { return "intel"; }
    
    @Override
    public HostConnector getHostConnector(InternetAddress hostAddress, String vendorConnectionString, TlsPolicy tlsPolicy) throws IOException {
        try {
            intelVendorConnectionString = vendorConnectionString;
            ConnectionString.IntelConnectionString intelConnectionString = ConnectionString.IntelConnectionString.forURL(vendorConnectionString);
            log.debug("IntelHostConnectorFactory: Connection string URL is {}", intelConnectionString.toURL());
            // We need to verify if the user has specified the login id and password for the host. If not, we will check in the pre-register host table.
            // If it is not even present in that table, we will throw an error.
            //Since creation of lib-hostconnector, user needs to feed user and encrypted password to the hostconnector 
//            if (intelConnectionString.getUsername() == null || intelConnectionString.getUsername().isEmpty() ||
//                    intelConnectionString.getPassword() == null || intelConnectionString.getPassword().isEmpty()) {
//                log.debug("IntelHostConnectorFactory - User name or password not specified. Retrieving from table");
//                MwHostPreRegistrationDetails hostLoginDetails = My.jpa().mwHostPreRegistrationDetails().findByName(intelConnectionString.getHost().toString());
//                if (hostLoginDetails != null) {
//                    ConnectionString tempConnectionString = ConnectionString.forIntel(intelConnectionString.getHost().toString(), intelConnectionString.getPort(), 
//                            hostLoginDetails.getLogin(), hostLoginDetails.getPassword());
//                    // Would be used to return back the modified connection string.
//                    intelVendorConnectionString = tempConnectionString.getConnectionString();
//                    log.debug("IntelHostConnectorFactory - URL of new connection string is {}", tempConnectionString.getURL());
//                    intelConnectionString = ConnectionString.IntelConnectionString.forURL(tempConnectionString.getConnectionString());
//                }
//            }
            intelVendorConnectionString = new ConnectionString(Vendor.INTEL, intelVendorConnectionString).getConnectionStringWithPrefix();
            URL url = intelConnectionString.toURL();
            if( url.getPort() == 1443 || url.getPath().contains("/v2") ) {
                // assume trust agent v2
                log.debug("Creating IntelHostConnector v2 for host {} with URL {}", hostAddress, url);
                Properties properties = new Properties();
                // mtwilson version 2.0 beta has authentication support on the trust agent but not yet in the mtwilson portal
                // so we use this default username and empty password until the mtwilson portal is updated to ask for trust agent
                // login credentials
                if( intelConnectionString.getUsername() != null ) {
                properties.setProperty("mtwilson.api.username", intelConnectionString.getUsername());
                }
                if( intelConnectionString.getPassword() != null ) {
                properties.setProperty("mtwilson.api.password", intelConnectionString.getPassword());
                }
                //log.info("== Username {}", intelConnectionString.getUsername());
                //log.info("== Password {}", intelConnectionString.getPassword());
                
//                properties.setProperty("mtwilson.api.username", "mtwilson");
//                properties.setProperty("mtwilson.api.password", "");
//                properties.setProperty("mtwilson.api.ssl.policy", "INSECURE");
                
                // now add the /v2 path if it's not already there,  to maintain compatibility with the existing UI that only prompts for
                // the hostname and port and doesn't give the user the ability to specify the complete connection url
                if( url.getPath().isEmpty() || url.getPath().equals("/") ) {
                    url = UriBuilder.fromUri(url.toURI()).replacePath("/v2").build().toURL();
                    log.debug("Rewritten intel host url: {}", url.toExternalForm());
                }
                TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
                return new IntelHostConnector(client, hostAddress);
            }
            else {
                //V1 is previous implementation, need to confir if it's being used by anyone or not.
                /*if( url.getPort() == 9999 )*/ 
                // assume trust agent v1
                 // assume trust agent v2
                log.debug("Creating IntelHostConnector v2 for host {} with URL {}", hostAddress, url);
                Properties properties = new Properties();
                // mtwilson version 2.0 beta has authentication support on the trust agent but not yet in the mtwilson portal
                // so we use this default username and empty password until the mtwilson portal is updated to ask for trust agent
                // login credentials
                if( intelConnectionString.getUsername() != null ) {
                properties.setProperty("mtwilson.api.username", intelConnectionString.getUsername());
                }
                if( intelConnectionString.getPassword() != null ) {
                properties.setProperty("mtwilson.api.password", intelConnectionString.getPassword());
                }
//                properties.setProperty("mtwilson.api.username", "mtwilson");
//                properties.setProperty("mtwilson.api.password", "");
//                properties.setProperty("mtwilson.api.ssl.policy", "INSECURE");
                
                // now add the /v2 path if it's not already there,  to maintain compatibility with the existing UI that only prompts for
                // the hostname and port and doesn't give the user the ability to specify the complete connection url
                if( url.getPath().isEmpty() || url.getPath().equals("/") ) {
                    url = UriBuilder.fromUri(url.toURI()).replacePath("/v2").build().toURL();
                    log.debug("Rewritten intel host url: {}", url.toExternalForm());
                }
                TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
                return new IntelHostConnector(client, hostAddress);
//               TrustAgentSecureClient client = new TrustAgentSecureClient(new TlsConnection(url, tlsPolicy));
//                log.debug("Creating IntelHostAgent v1 for host {}", hostAddress); // removed  vendorConnectionString to prevent leaking secrets  with connection string {}
//                return new IntelHostConnector(client, hostAddress);
            }
        }
        catch(Exception e) {
            throw new IOException("Cannot get trust agent client for host: "+hostAddress.toString()+": "+e.toString(), e);
        }
    }

    @Override
    public HostConnector getHostConnector(String vendorConnectionString, TlsPolicy tlsPolicy) throws IOException {
        try {
            URL url = new URL(vendorConnectionString.substring(0, vendorConnectionString.indexOf(";")));
            InternetAddress hostAddress = new InternetAddress(url.getHost());
            return getHostConnector(hostAddress, vendorConnectionString, tlsPolicy);
        }
        catch(Exception e) {
            throw new IOException(String.format("Cannot get trust agent client for host connection: %s: %s",
                    vendorConnectionString, e.toString()), e);
        }
    }

    @Override
    public String getVendorConnectionString() {
        return intelVendorConnectionString;
    }
}
