/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.host.connector;

import com.intel.dcsg.cpg.net.InternetAddress;
import com.intel.mtwilson.core.common.datatypes.ConnectionString;
import com.intel.mtwilson.core.common.model.HostInfo;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
import com.intel.dcsg.cpg.extensions.Plugins;
import com.intel.mtwilson.tls.policy.TlsPolicyDescriptor;
import com.intel.mtwilson.tls.policy.factory.TlsPolicyFactoryUtil;
import java.io.IOException;

/**
 * Use this class to instantiate the appropriate connector or client for a given
 * host.
 *
 * 
 * @author zaaquino
 */
public class HostConnectorFactory {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(HostConnectorFactory.class);
    
    private String hostConnectionString = "";
    
    public String getHostConnectionString() {
        return hostConnectionString;
    }
    
    public HostConnector getHostConnector(ConnectionString connectionString, TlsPolicyDescriptor tlsPolicyDescriptor) throws IOException {
        TlsPolicy tlsPolicy = TlsPolicyFactoryUtil.createTlsPolicy(tlsPolicyDescriptor);
        return getHostConnector(connectionString, tlsPolicy);
    }
    
    public HostConnector getHostConnector(ConnectionString connectionString, TlsPolicy tlsPolicy) throws IOException {
        if (connectionString == null) {
            throw new IllegalArgumentException("Connection info missing");
        }
        String vendorProtocol = connectionString.getVendor().name().toLowerCase();
        log.debug("Vendor Protocol searched: {}", vendorProtocol);
        VendorHostConnectorFactory factory = Plugins.findByAttribute(VendorHostConnectorFactory.class, "vendorProtocol", vendorProtocol);
        if (factory != null) {
            HostConnector hostConnector = factory.getHostConnector(connectionString.getConnectionString(), tlsPolicy);
            hostConnectionString = factory.getVendorConnectionString();
            return hostConnector;
        }
        throw new UnsupportedOperationException("No agent factory registered for this host");
    }
    
    public HostConnector getHostConnector(String connectionString, TlsPolicyDescriptor tlsPolicyDescriptor) {
        TlsPolicy tlsPolicy = TlsPolicyFactoryUtil.createTlsPolicy(tlsPolicyDescriptor);
        return getHostConnector(connectionString, tlsPolicy);
    }
    
    public HostConnector getHostConnector(String connectionString, TlsPolicy tlsPolicy) {
        /*  Sample connString input:
                vmware:https://vcenter:443;h=hostname;u=username;p=password
                intel:https://hostip:1443;u=username;p=password*/
        /*TODO 
          - The way the string is currently being parsed should be improved
          - Accepted strings with u and p parameters needs to be checked, might not be implemented yet
        */
        
        String hostIP = connectionString.substring(connectionString.indexOf("//") + 2, connectionString.length());
        hostIP = hostIP.substring(0, hostIP.indexOf(":"));
        HostInfo hostInfo = new HostInfo();
        hostInfo.setHostName(hostIP);
        
        try {
            return getHostConnector(hostInfo, connectionString, tlsPolicy);
        } catch (Exception e) {
            String address = hostIP;
            if (address == null || address.isEmpty()) {
                address = "We need to get the IP FROM SOMEWHERE";
            }
            throw new IllegalArgumentException(String.format("Cannot create Host Agent for %s", address), e);
        }
    }
    
    private HostConnector getHostConnector(HostInfo host, String connectionString, TlsPolicy tlsPolicy) {
        String address = host.getHostName();
        
        try {
            InternetAddress hostAddress = new InternetAddress(address); // switching from Hostname to InternetAddress (better support for both hostname and ip address)
            ConnectionString connectionStringObj;
            connectionStringObj = ConnectionString.from(host, connectionString);
            log.debug("Retrieving TLS policy...");
            log.debug("Creating Host Agent for host: {}", address);
            HostConnector hc = getHostConnector(hostAddress, connectionStringObj, tlsPolicy);
            log.debug("HostConnector successfully created");
            return hc;
        } catch (Exception e) {
            throw new IllegalArgumentException(String.format("Cannot create Host Agent for %s", address), e);
        }
    }
    
    /**
     *
     * @param connectionString what is also known as the
     * "AddOn_Connection_String", in the form vendor:url, for example
     * vmware:https://vcenter.com/sdk;Administrator;password
     * @return
     */
    private HostConnector getHostConnector(InternetAddress hostAddress, ConnectionString connectionString, TlsPolicy tlsPolicy) throws IOException {
        if (connectionString == null) {
            throw new IllegalArgumentException("Connection info missing");
        }
        String vendorProtocol = connectionString.getVendor().name().toLowerCase(); // INTEL, CITRIX, VMWARE becomes intel, citrix, vmware

        /*treat use intel host agent for microsoft
         if (vendorProtocol.compareTo("microsoft") == 0) {
         vendorProtocol = "intel";
         }
         */
        VendorHostConnectorFactory factory = Plugins.findByAttribute(VendorHostConnectorFactory.class, "vendorProtocol", vendorProtocol);
        if (factory != null) {
            HostConnector hostConnector = factory.getHostConnector(hostAddress, connectionString.getConnectionString(), tlsPolicy);
            hostConnectionString = factory.getVendorConnectionString();
            return hostConnector;
        }
        log.error("HostConnectorFactory: Unsupported host type: {}", vendorProtocol);
        throw new UnsupportedOperationException(String.format("Unsupported host type: %s", vendorProtocol));
    }
}
