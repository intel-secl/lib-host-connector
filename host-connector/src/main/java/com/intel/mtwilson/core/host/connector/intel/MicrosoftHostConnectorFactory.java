/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.host.connector.intel;

import com.intel.mtwilson.core.common.utils.AASTokenFetcher;
import com.intel.mtwilson.core.host.connector.HostConnector;
import com.intel.mtwilson.core.host.connector.VendorHostConnectorFactory;
import com.intel.dcsg.cpg.net.InternetAddress;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
import com.intel.mtwilson.core.common.datatypes.ConnectionString;
import com.intel.mtwilson.core.common.datatypes.Vendor;
import com.intel.mtwilson.core.common.trustagent.client.jaxrs.TrustAgentClient;
import java.io.IOException;
import java.net.URL;
import java.util.Properties;
import javax.ws.rs.core.UriBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The MicrosoftHostConnectorFactory creates instances of IntelHostConnector. It does
 * not create instances of IntelClient. It uses the IntelClientFactory to do that.
 * @author hxia5
 */
public class MicrosoftHostConnectorFactory implements VendorHostConnectorFactory {
    private Logger log = LoggerFactory.getLogger(getClass());
    private String microsoftVendorConnectionString = "";
    
    @Override
    public String getVendorProtocol() { return "microsoft"; }
    
    @Override
    public HostConnector getHostConnector(InternetAddress hostAddress, String vendorConnectionString, String aasApiUrl, TlsPolicy tlsPolicy) throws IOException {
        try {
            microsoftVendorConnectionString = vendorConnectionString;  //the vendorConnectionString parameter only contains the URL portion
            String tempMicrosoftVendorConnectionString = new ConnectionString(Vendor.MICROSOFT, vendorConnectionString).getConnectionStringWithPrefix();
            ConnectionString.MicrosoftConnectionString microsoftConnectionString = ConnectionString.MicrosoftConnectionString.forURL(tempMicrosoftVendorConnectionString);
            microsoftVendorConnectionString = new ConnectionString(Vendor.MICROSOFT, microsoftVendorConnectionString).getConnectionStringWithPrefix();
            URL url = microsoftConnectionString.toURL();
            if( url.getPort() == 1443 || url.getPath().contains("/v2") ) {
                // now add the /v2 path if it's not already there,  to maintain compatibility with the existing UI that only prompts for
                // the hostname and port and doesn't give the user the ability to specify the complete connection url
                if( url.getPath().isEmpty() || url.getPath().equals("/") ) {
                    url = UriBuilder.fromUri(url.toURI()).replacePath("/v2").build().toURL();
                }
            }
            Properties properties = new Properties();
            properties.setProperty("bearer.token", new AASTokenFetcher().getAASToken(microsoftConnectionString.getUsername(), microsoftConnectionString.getPassword(), new TlsConnection(new URL(aasApiUrl), tlsPolicy)));
            TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
            return new IntelHostConnector(client, hostAddress);
        }
        catch(Exception e) {
            throw new IOException(String.format("Cannot get trust agent client for host: %s: %s", hostAddress.toString(), e.toString()), e);
        }
    }

    @Override
    public HostConnector getHostConnector(String vendorConnectionString, String aasApiUrl, TlsPolicy tlsPolicy) throws IOException {
        try {
            URL url = new URL(vendorConnectionString.substring(0, vendorConnectionString.indexOf(";")));
            InternetAddress hostAddress = new InternetAddress(url.getHost());
            return getHostConnector(hostAddress, vendorConnectionString, aasApiUrl, tlsPolicy);
        }
        catch(Exception e) {
            throw new IOException(String.format("Cannot get trust agent client for host connection: %s", e.toString()), e);
        }
    }

    @Override
    public String getVendorConnectionString() {
        return microsoftVendorConnectionString;
    }
}
