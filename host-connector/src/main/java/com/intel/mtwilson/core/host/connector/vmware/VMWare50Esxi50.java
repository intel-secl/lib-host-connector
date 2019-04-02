/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.host.connector.vmware;

import com.intel.mtwilson.core.common.model.Pcr;
import com.intel.mtwilson.core.common.model.PcrManifest;
import com.intel.mtwilson.core.common.model.PcrSha1;
import com.vmware.vim25.HostTpmDigestInfo;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VMWare50Esxi50   {
    private static Logger log = LoggerFactory.getLogger(VMWare50Esxi50.class);
	

    
    /**
     * ESX 5.0 does not support module/event logs so this method is the same as calling createPcrManifestFromVmwareHostTpmDigestInfo
     * @param htdis is a list of HostTpmDigestInfo java model object.
     * @return PcrManifest java model object.
     */
    public static PcrManifest createPcrManifest(List<HostTpmDigestInfo> htdis) {
        PcrManifest pcrManifest = new PcrManifest();
		for (HostTpmDigestInfo htdi : htdis) {
            // this block just out of curiosity ... we should instantiate the right digest class using this info. expected to be SHA1... always...
            String algorithm = htdi.getDigestMethod();
            log.debug("HostTpmDigestInfo DigestMethod = {}", algorithm);
            // convert the vwmare data types to mt wilson datatypes
            String digest = VMwareClient.byteArrayToHexString(htdi.getDigestValue());
            Pcr pcr = new PcrSha1(htdi.getPcrNumber(), digest);
            pcrManifest.setPcr(pcr);
        }        
        return pcrManifest;
    }
	
	
	
}
