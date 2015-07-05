package com.securesean.forensics.sdb;

import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;

/**
 *
 * @author Sean
 */
public class SdbModuleIngestJobSettings implements IngestModuleIngestJobSettings{

    @Override
    public long getVersionNumber() {
        return (long) 1.0;    
    }
    
}
