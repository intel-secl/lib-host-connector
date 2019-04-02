/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.host.connector.vmware;

/**
 *
 * @author jbuhacoff
 */
public class VMwareConnectionException extends Exception {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public VMwareConnectionException() {
        super();
    }
    public VMwareConnectionException(Throwable cause) {
        super(cause);
    }
    public VMwareConnectionException(String message) {
        super(message);
    }
    public VMwareConnectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
