/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.host.connector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.core.common.model.HostManifest;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Use this class to instantiate the appropriate connector or client for a given
 * host.
 * @throws UnuspportedOperationException if the appropriate agent type cannot be determined from the given host
 * @author zaaquino
 */
public class HostConnectorFactoryTest {
    private static final Logger log = LoggerFactory.getLogger(HostConnectorFactoryTest.class);
    private final ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
    
    @BeforeClass
    public static void setUpClass() throws Exception {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }
    
    @Test
    public void serializeHostManifest() throws Exception {
        String hostManifestAsJson = Resources.toString(Resources.getResource("host-manifest-rhel-tpm2.json"), Charsets.UTF_8);
        HostManifest hostManifest = mapper.readValue(hostManifestAsJson, HostManifest.class);
        System.out.println(String.format("Successfully deserialized file to host manifest with host name: %s", hostManifest.getHostInfo().getHostName()));
        
        System.out.println(String.format("Serialized host manifest:\n%s", mapper.writeValueAsString(hostManifest)));
    }
}
