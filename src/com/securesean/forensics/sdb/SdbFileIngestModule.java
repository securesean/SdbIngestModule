package com.securesean.forensics.sdb;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.sleuthkit.autopsy.ingest.IngestMessage;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.util.Random;
import java.util.logging.Level;
import javax.swing.JOptionPane;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.netbeans.api.progress.ProgressHandle;
import org.netbeans.api.progress.ProgressHandleFactory;

import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.MessageNotifyUtil;
import org.sleuthkit.autopsy.coreutils.MessageNotifyUtil.Notify;
import org.sleuthkit.autopsy.datamodel.ContentUtils.ExtractFscContentVisitor;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.ModuleDataEvent;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;

/**
 *
 * @author Sean
 */
public class SdbFileIngestModule implements FileIngestModule {

    private IngestJobContext context;
    private Boolean initialized = false;
    private Logger logger;
    private final byte[] magic;
    private String toolPath;
    private String toolName;
    private String tempSdbFileName;
    private File workingDirFile;
    private String workingDirSting;
    private File tempSdbFile;
    private boolean userWantsMessages;
    private String moduleName;

    public SdbFileIngestModule() {
        this.magic = new byte[]{(byte) 0x73, (byte) 0x64, (byte) 0x62, (byte) 0x66};
    }

    @Override
    public void startUp(IngestJobContext ijc) throws IngestModuleException {
        Random randomGenerator = new Random();

        this.moduleName = "SDB Ingest Module";
        this.logger = IngestServices.getInstance().getLogger(SdbFileIngestModule.class.getName());
        this.context = ijc;
        this.initialized = true;
        this.toolPath = "C:\\";
        this.toolName = "sdb-explorer.exe";
        this.tempSdbFileName = "temp_" + context.getJobId() + "_" + randomGenerator.nextInt(1000) + ".sdb";
        this.workingDirSting = "C:\\Users\\Sean\\Desktop\\";
        this.workingDirFile = new File(workingDirSting);
        this.userWantsMessages = true;
        this.tempSdbFile = new File(workingDirSting + tempSdbFileName);
    }

    @Override
    public void shutDown() {
        // if there was an sdb file copied out then delete it
    }

    @Override
    public ProcessResult process(AbstractFile file) {

        if (initialized != true) { //error initializing the module
            logger.log(Level.WARNING, "Skipping processing, module not initialized, seansean file: {0}", file.getName());
            return ProcessResult.valueOf("Module not initalized");
        }

        // Skip NSRL / known files. if the config allows it :D
        //if (skipKnownFiles && file.getKnown() == TskData.FileKnown.KNOWN) {
        //    return IngestModule.ProcessResult.OK;
        //}
        
        logger.log(Level.INFO, "Checking SDB file seansean");
        if (file.isFile() & isSDB(file)) {
            try {
                extractInformation(file);
            } catch (IOException ex) {
                logger.log(Level.SEVERE, "Unable to find File seansean: {0}", ex);
                JOptionPane.showMessageDialog(null, ex);
                return ProcessResult.ERROR;
            } catch (InterruptedException ex) {
                logger.log(Level.SEVERE, "External Process Launch was interrupted: {0}", ex);
                return ProcessResult.ERROR;
            }
        }

        return ProcessResult.OK;
    }

    private boolean isSDB(AbstractFile file) {
        logger.log(Level.INFO, "Checking file: {0}", file.getName());
        int offset = 8;
        if (file.canRead() & (file.getSize() > (magic.length + offset))) {
            byte[] buf = new byte[magic.length];

            try {
                if ((file.read(buf, 8, magic.length) == magic.length) & (Arrays.equals(buf, magic))) {
                    return true;
                }
            } catch (TskCoreException ex) {
                Logger.getLogger(SdbFileIngestModule.class.getName()).log(Level.SEVERE, "Error reading file: {0}", file.getName());
            }
        } else {
            logger.log(Level.INFO, "Unable to Read file: {0}", file.getName());
        }
        return false;
    }

    private void extractInformation(AbstractFile file) throws IOException, InterruptedException {
        ProgressHandle ph = ProgressHandleFactory.createHandle(moduleName);
        ExtractFscContentVisitor.extract(file, tempSdbFile, ph, null);

        ProcessBuilder pb = new ProcessBuilder(toolPath + toolName, "-t", tempSdbFile.getPath());

        //pb.directory(workingDir);
        //pb.directory(new File("C:\\Windows\\System32\\"));
        Process process = pb.start();

        InputStream is = process.getInputStream();
        InputStreamReader isr = new InputStreamReader(is);
        BufferedReader br = new BufferedReader(isr);

        //OutputStream stdout = p.getOutputStream();
        //InputStream errout = p.getErrorStream();
        //
        //
        //get stdout
        StringBuilder outputBuffer = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            outputBuffer.append(line).append("\n");
        }

        if (process.waitFor() == 0) {
            logger.log(Level.INFO, "sdb-explorer finished normally: {0}", file.getName());
        } else {
            logger.log(Level.INFO, "sdb-explorer finished abnormally: {0}", file.getName());

            //errout
            if (userWantsMessages) {
                //Messages are created using the org.sleuthkit.autopsy.ingest.IngestMessage class and posted to the inbox using the org.sleuthkit.autopsy.ingest.IngestServices.postMessage() method
                IngestServices.getInstance().postMessage(IngestMessage.createMessage(IngestMessage.MessageType.WARNING, moduleName, "sdb-explorer finished abnormally"));
            }
        }

        // report it to the other modules;
        BlackboardAttribute bba = new BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DESCRIPTION.getTypeID(),
                moduleName,
                outputBuffer.toString());

        try {
            // Fire an event to notify any listeners for blackboard postings.
            BlackboardArtifact bb_artifact = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_TOOL_OUTPUT);
            bb_artifact.addAttribute(bba);

            ModuleDataEvent event = new ModuleDataEvent(moduleName, ARTIFACT_TYPE.TSK_GEN_INFO);
            IngestServices.getInstance().fireModuleDataEvent(event); //Collections.singletonList(badFile)

            if (userWantsMessages) {
                // Messages are created using the org.sleuthkit.autopsy.ingest.IngestMessage class and posted to the inbox using the org.sleuthkit.autopsy.ingest.IngestServices.postMessage() method
                IngestMessage message = IngestMessage.createMessage(IngestMessage.MessageType.INFO, moduleName, "sdb-explorer finished Normally. SDB file targeting: " + file.getName());
                IngestServices.getInstance().postMessage(message);

                //org.sleuthkit.autopsy.ingest.IngestMessage class and posted to the inbox using the org.sleuthkit.autopsy.ingest.IngestServices.postMessage() 
                Notify.show("SDB File Found!", "Shim Database file Found. This may indicate advanced peresistence found in advanced malware", MessageNotifyUtil.MessageType.INFO);

                // display it
                //JOptionPane.showMessageDialog(null, outputBuffer.toString());
            }

        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Unable to add Attribute to Artifact on the Blackboard: {0}", ex);
        }

        // clean up - delete the extracted sdb file
        try {
            logger.log(Level.INFO, "Deleting the temp sdb file: {0}", tempSdbFile.toPath());
            Files.delete(tempSdbFile.toPath());
        } catch (NoSuchFileException x) {
            logger.log(Level.WARNING, "No Such File Error when deleting the temp sdb file: {0}", tempSdbFile.toPath());
        } catch (DirectoryNotEmptyException x) {
            logger.log(Level.WARNING, "Error when Deleting the temp sdb file: {0}", tempSdbFile.toPath());
        } catch (IOException x) {
            // File permission problems are caught here.
            logger.log(Level.SEVERE, "Permissions Error when Deleting the temp sdb file: {0}", x);
        }

    }// end of extract

}// end of class
