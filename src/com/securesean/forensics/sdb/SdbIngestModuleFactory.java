package com.securesean.forensics.sdb;

import org.openide.util.lookup.ServiceProvider;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.ingest.IngestModuleFactoryAdapter;
import org.sleuthkit.autopsy.ingest.IngestModuleGlobalSettingsPanel;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;

/**
 *
 * @author Sean
 */
@ServiceProvider(service = IngestModuleFactory.class)
public class SdbIngestModuleFactory extends IngestModuleFactoryAdapter implements IngestModuleFactory {

    @Override
    public String getModuleDisplayName() {
        return "Shim Database file Extractor";
    }

    @Override
    public String getModuleDescription() {
        return "Displays information on Shim Database files which are created for application compatability or malicious persistence";
    }

    @Override
    public String getModuleVersionNumber() {
        return "1";
    }

    @Override
    public boolean hasGlobalSettingsPanel() {
        return false;
    }

    @Override
    public IngestModuleGlobalSettingsPanel getGlobalSettingsPanel() {
        throw new UnsupportedOperationException("Not supported yet - No job settings"); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public IngestModuleIngestJobSettings getDefaultIngestJobSettings() {
        // ask for location of sdb-explorer - if one is not found go to
        return new SdbModuleIngestJobSettings();
    }

    @Override
    public boolean hasIngestJobSettingsPanel() {
        return false;
    }

    @Override
    public IngestModuleIngestJobSettingsPanel getIngestJobSettingsPanel(IngestModuleIngestJobSettings imijs) {
        return new SdbModuleIngestJobSettingsPanel();
    }

    @Override
    public boolean isDataSourceIngestModuleFactory() {
        return false;
    }

    @Override
    public DataSourceIngestModule createDataSourceIngestModule(IngestModuleIngestJobSettings imijs) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        
    }

    @Override
    public boolean isFileIngestModuleFactory() {
        return true;
    }

    @Override
    public FileIngestModule createFileIngestModule(IngestModuleIngestJobSettings imijs) {
        return new SdbFileIngestModule();
    }
    
}
