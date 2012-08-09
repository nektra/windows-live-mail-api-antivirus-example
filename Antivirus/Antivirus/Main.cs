using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Microsoft.Win32;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using NktWLMailApi;
using NktWLMailApiInit;
using NktWLMailStore;
using nClam;

namespace Antivirus
{
    public class Main
    {
        static string pluginsKey = "Software\\Nektra\\WLMailApi\\Plugins";
        static string pluginValueName = "AntivirusDemo";
        static string pluginValueData = "Antivirus.Main";
        private NktWLMailApiInit.WLMailApiInit wlmailApiInit;
        private NktWLMailApi.WLMailApi wlmailApiCore;
        private NktWLMailStore.FolderManager folderManager;
        private NktWLMailStore.MailAccountManager accountManager;
        private Utils utils;
        private nClam.ClamClient clamClient;
        private const string CLAM_HOST = "localhost";
        private const int CLAM_PORT = 3310;



        [ComRegisterFunctionAttribute]
        public static void RegisterFunction(Type t)
        {
            RegistryKey key = Registry.LocalMachine.OpenSubKey(pluginsKey, true);
            if (key == null)
            {
                key = Registry.LocalMachine.CreateSubKey(pluginsKey);
                if (key == null)
                {
                    System.Windows.Forms.MessageBox.Show("Error registering component");

                    return;
                }
            }

            key.SetValue(pluginValueName, pluginValueData);
            key.Close();
        }

        [ComUnregisterFunctionAttribute]
        public static void UnregisterFunction(Type t)
        {
            RegistryKey key = Registry.LocalMachine.OpenSubKey(pluginsKey, true);
            if (key == null)
            {
                return;
            }

            key.DeleteValue(pluginValueName, false);
            key.Close();
        }

        public Main()
        {
            wlmailApiInit = new NktWLMailApiInit.WLMailApiInit();
            wlmailApiInit.OnInit += new NktWLMailApiInit.IWLMailApiInitEvents_OnInitEventHandler(wlmailApiInit_OnInit);
            wlmailApiInit.OnShutdown += new NktWLMailApiInit.IWLMailApiInitEvents_OnShutdownEventHandler(wlmailApiInit_OnShutdown);

        }

        void wlmailApiInit_OnShutdown()
        {
            wlmailApiCore = null;
            wlmailApiInit.OnInit -= new NktWLMailApiInit.IWLMailApiInitEvents_OnInitEventHandler(wlmailApiInit_OnInit);
            wlmailApiInit.OnShutdown -= new NktWLMailApiInit.IWLMailApiInitEvents_OnShutdownEventHandler(wlmailApiInit_OnShutdown);

            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }

        void wlmailApiInit_OnInit()
        {
            wlmailApiCore = new NktWLMailApi.WLMailApi();
            folderManager = new NktWLMailStore.FolderManager();
            accountManager = new NktWLMailStore.MailAccountManager();

            utils = new Utils(wlmailApiCore, folderManager, accountManager);

            this.clamClient = new ClamClient(CLAM_HOST, CLAM_PORT);

            this.wlmailApiCore.OnDatabaseChange += new NktWLMailApi.IWLMailApiEvents_OnDatabaseChangeEventHandler(wlmailApiCore_OnDatabaseChange);
        }

        void wlmailApiCore_OnDatabaseChange(NktWLMailApi.tagDATABASE_TRANSACTION dt, ulong folderId, ulong objId, ulong newParentId)
        {
            var folder = folderManager.GetFolder(folderId);

            if (utils.IsFromQuickViews(folder) || !ShouldBeHandled(dt))
            {
                utils.ReleaseComObject(folder);
                return;
            }

            var message = folder.GetMessage((int)objId);

            switch (dt)
            {
                case tagDATABASE_TRANSACTION.NKT_TR_INSERT_MESSAGE:
                    if (folder.IsSent() == 0 && folder.IsOutbox() == 0)
                    {
                        List<string> virusList = MessageAttachmentsContainViruses(message);

                        if (virusList.Count > 0)
                        {
                            string virusNames = "";
                            foreach (string virusName in virusList)
                            {
                                if (virusNames != "")
                                    virusNames += "," + virusName;
                                else
                                    virusNames = virusName;
                            }
                            MessageBox.Show(string.Format("The message contains the following viruses: {0}", virusNames));
                        }
                    }
                    break;
            }
            utils.ReleaseComObject(message);
            utils.ReleaseComObject(folder);
        }

        private string ClamAntiVirusScanning(string filename) {
            var scanResult = this.clamClient.ScanFileOnServer("c:\\users\\Admin\\Desktop\\Temp");

            switch (scanResult.Result)
            {
                case ClamScanResults.Clean:
                    return null;
                    break;

                case ClamScanResults.VirusDetected:
                    return scanResult.InfectedFiles.First().VirusName;
                    break;

                case ClamScanResults.Error:
                    return null;
                    break;
            }

            return null;
            
        }

        private string GetTemporaryDirectory() // http://stackoverflow.com/questions/278439/creating-a-temporary-directory-in-windows
        {
            string tempDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            Directory.CreateDirectory(tempDirectory);
            return tempDirectory;
        }

        private List<string> MessageAttachmentsContainViruses(NktWLMailStore.Message message)
        {
            List<string> virusList = new List<string>();

            var attachment = message.GetFirstAttachment();
            string temporaryDirectory = this.GetTemporaryDirectory();

            while (attachment != 0)
            {
                string fullpath = Path.Combine(temporaryDirectory, message.GetFilename(attachment).ToLower() + Path.GetRandomFileName());

                if (message.SaveBodyToFile(attachment, fullpath, 0) == 0)
                {
                    utils.ShowMsgBox("An error occurred while saving message attachments.");

                    break;
                }

                string scanResultString = ClamAntiVirusScanning(fullpath);
                if (scanResultString != null)
                {
                    virusList.Add(scanResultString);
                }

                attachment = message.GetNextAttachment();
            }

            utils.ReleaseComObject(message);

            return virusList;
        }        

        private bool ShouldBeHandled(tagDATABASE_TRANSACTION dt)
        {
            return (dt == tagDATABASE_TRANSACTION.NKT_TR_INSERT_MESSAGE ||
                    dt == tagDATABASE_TRANSACTION.NKT_TR_DELETE_MESSAGE ||
                    dt == tagDATABASE_TRANSACTION.NKT_TR_RENAME_FOLDER ||
                    dt == tagDATABASE_TRANSACTION.NKT_TR_DELETE_FOLDER);
        }
    }

    // Do not pay attention to this class.
    public class WindowWrapper : IWin32Window
    {
        public WindowWrapper(IntPtr handle)
        {
            _hwnd = handle;
        }

        public IntPtr Handle
        {
            get { return _hwnd; }
        }

        private readonly IntPtr _hwnd;
    }
}
