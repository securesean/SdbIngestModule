package com.securesean.forensics.sdb;

import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;

/**
 *
 * @author Sean
 */
class SdbModuleIngestJobSettingsPanel extends IngestModuleIngestJobSettingsPanel {

    public SdbModuleIngestJobSettingsPanel() {
    }

    @Override
    public IngestModuleIngestJobSettings getSettings() {
        // ask where the sdb-explorer.exe is
        return new SdbModuleIngestJobSettings();
    }
    
}
