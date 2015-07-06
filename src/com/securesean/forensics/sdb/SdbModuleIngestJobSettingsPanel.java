package com.securesean.forensics.sdb;

import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;
import javax.swing.JLabel;
import javax.swing.JFileChooser;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.io.File;
import javax.swing.JOptionPane;
import java.awt.GridLayout;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import javax.swing.JCheckBox;
import javax.swing.JTextArea;
import javax.swing.filechooser.FileFilter;

/**
 *
 * @author Sean
 */
class SdbModuleIngestJobSettingsPanel extends IngestModuleIngestJobSettingsPanel {
    JLabel topText;
    JLabel toolPathLabel;
    JLabel WorkingDirLabel;
    JFileChooser fileChooser;
    //JFileChooser WorkingDir;
    JButton selectToolPath;
    JButton selectWorkingDir;
    JCheckBox userMessagesCheckBox;
    JCheckBox deleteExtractedFilesCheckBox;
    JButton enterToolParamers;
    SdbModuleIngestJobSettings settings;
    
    public SdbModuleIngestJobSettingsPanel() {
        settings = new SdbModuleIngestJobSettings();
        GridLayout grid = new GridLayout(5, 2, 5, 5);
        setLayout(grid);
        
        
        topText = new JLabel("Shim Database (SDB) File Extractor");
        add(topText);
        add(new JLabel("By Sean Pierce"));
        
        selectToolPath = new JButton("Select Tool Path");
        selectWorkingDir = new JButton("Select SDB File Extraction");
        
        commandHandler handleCommands = new commandHandler();
        selectToolPath.addActionListener(handleCommands);
        selectWorkingDir.addActionListener(handleCommands);
        
        
        add(selectToolPath);
        
        toolPathLabel = new JLabel(settings.getTool().getPath());
        add(toolPathLabel);
        
        add(selectWorkingDir);
        
        WorkingDirLabel = new JLabel(settings.getWorkingDir().getPath());
        add(WorkingDirLabel);
        
        // now make the file chooser object that the button will prompt
        fileChooser = new JFileChooser();
        //WorkingDir = new JFileChooser();
        
        
        //userMessagesTextArea = new JTextArea(settings.getToolParams());
        //userMessagesTextArea.add addActionListener(handleCommands);
        //add(userMessagesTextArea);
        enterToolParamers = new JButton("Enter Tool Parameters");
        enterToolParamers.addActionListener(handleCommands);
        add(enterToolParamers);
        add(new JLabel());  // just to even out the rows
        
        CheckBoxHandler itemHandler = new CheckBoxHandler();
        userMessagesCheckBox = new JCheckBox("Display user runtime messages");
        userMessagesCheckBox.setSelected(true);
        userMessagesCheckBox.addItemListener(itemHandler);
        add(userMessagesCheckBox);
        //add(new JLabel());  // just to even out the rows
        
        deleteExtractedFilesCheckBox = new JCheckBox("Delete Extracted Files After Processing");
        deleteExtractedFilesCheckBox.setSelected(false);
        deleteExtractedFilesCheckBox.addItemListener(itemHandler);
        add(deleteExtractedFilesCheckBox);
        //add(new JLabel());  // just to even out the rows
        
        
    }

    @Override
    public IngestModuleIngestJobSettings getSettings() {
        // ask where the sdb-explorer.exe is
        return settings;
    }
    
    public IngestModuleIngestJobSettings getDefaultIngestJobSettings(){
        // ask where the sdb-explorer.exe is
        //settings = new SdbModuleIngestJobSettings();
        
        //settings.setToolName("sdb-explorer.exe");
        //settings.setToolPath("C:\\");
        settings.setTool(new File("C:\\sdb-explorer.exe"));
        settings.setUserWantsMessages(true);
        File workingDir = new File(System.getProperty("user.home") + "\\Desktop\\ExtractedSDBFiles\\");
        settings.setWorkingDir(workingDir);
        settings.setToolParams("-t");
        
        return settings;
    }
    
        /**
     * Handles everything in the command panel
     * 
     */
    private class CheckBoxHandler implements ItemListener{

        @Override
        public void itemStateChanged(ItemEvent e) {
            if (e.getSource() == userMessagesCheckBox){
                if(e.getStateChange() == ItemEvent.DESELECTED)
                {
                    settings.setUserWantsMessages(false);
                } else if (e.getStateChange() == ItemEvent.SELECTED)
                {
                    settings.setUserWantsMessages(true);
                }else {
                    JOptionPane.showMessageDialog(null, "There was some Check Box selection Error - Please Try again");
                }
                
            }  else if (e.getSource() == deleteExtractedFilesCheckBox){
                if(e.getStateChange() == ItemEvent.DESELECTED)
                {
                    settings.setKeepExtractedFiles(true);
                }
                else if (e.getStateChange() == ItemEvent.SELECTED)
                {
                    settings.setKeepExtractedFiles(false);
                }
            }
        }
        
    }
    private class commandHandler implements ActionListener
    {

        @Override
        public void actionPerformed(ActionEvent event) {
            
            if (event.getSource() == enterToolParamers){
                settings.setToolParams(JOptionPane.showInputDialog("Enter Tool Parameters",settings.getToolParams()));
            }
            else if(event.getSource() == selectToolPath){
                //fileChooser.setFileFilter(); later
                fileChooser.setDialogTitle("Choose SDB Analysis Tool");
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                int returnVal = fileChooser.showDialog(null, "Select SDB Analysis Application");
            
                switch(returnVal){
                    case JFileChooser.CANCEL_OPTION:
                        JOptionPane.showMessageDialog(null, "Please select the local executable to analysis SDB files. If you have none download and compile Jon Erickson's sdb-exeplorer: https://github.com/evil-e/sdb-explorer");
                        break;
                    case JFileChooser.APPROVE_OPTION:
                        File selected = fileChooser.getSelectedFile();
                        if(!selected.canExecute()){
                            JOptionPane.showMessageDialog(null, "Please select the local executable to analysis SDB files. If you have none download and compile Jon Erickson's sdb-exeplorer: https://github.com/evil-e/sdb-explorer");
                            break;
                        }
                        settings.setTool(selected);
                        toolPathLabel.setText(selected.getPath());

                        break;
                    case JFileChooser.ERROR_OPTION:
                        JOptionPane.showMessageDialog(null, "There was some selection Error - Please Try again");
                        break;
                }
            } else if (event.getSource() == selectWorkingDir){
                //fileChooser.setFileFilter();
                fileChooser.setDialogTitle("Choose Folder SDB Extraction Destination");
                fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                
                int returnVal = fileChooser.showDialog(null, "Select SDB Extraction Destination Folder");
                switch(returnVal){
                    case JFileChooser.CANCEL_OPTION:
                        JOptionPane.showMessageDialog(null, "Please select a folder to stored the extracted SDB files.");
                        break;
                    case JFileChooser.APPROVE_OPTION:
                        File selected = fileChooser.getSelectedFile();
                        settings.setWorkingDir(selected);
                        WorkingDirLabel.setText(selected.getPath());
                        break;
                    case JFileChooser.ERROR_OPTION:
                        JOptionPane.showMessageDialog(null, "There was some selection Error - Please Try again");
                        break;
                }// end switch
                
            }// end else if
            
        } // actionPerformed

    }// end action listen
}


