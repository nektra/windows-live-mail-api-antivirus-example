using System;
using System.Globalization;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using NktWLMailApi;
using NktWLMailApiInit;
using NktWLMailStore;
using System.Windows.Forms;
using Message = NktWLMailStore.Message;

namespace Antivirus
{
    public class Utils
    {
        private WLMailApi _wlmailApiCore;
        private FolderManager _folderManager;
        private MailAccountManager _accountManager;

        private const ulong QuickViewsFolderID = 7;

        public Utils(WLMailApi wlmailApiCore, FolderManager folderManager, MailAccountManager accountManager)
        {
            _wlmailApiCore = wlmailApiCore;
            _folderManager = folderManager;
            _accountManager = accountManager;
        }

        public void ShowMsgBox(string text)
        {
            ShowMsgBoxHwnd(_wlmailApiCore.GetMainWindow(), text);
        }

        public void ShowMsgBox(IntPtr ownerWindow, string text)
        {
            ShowMsgBoxHwnd((int)ownerWindow, text);
        }

        private static void ShowMsgBoxHwnd(int hwnd, string text)
        {
            MessageBox.Show(new WindowWrapper((IntPtr)hwnd), text, @"WLMailApi", MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
        }

        public Message GetFirstSelectedMessage()
        {
            var folder = GetCurrentFolder();

            var messageID = _wlmailApiCore.GetFirstSelectedMessageID();

            var message = folder.GetMessage(messageID);

            ReleaseComObject(folder);

            return message.GetID() == -1 ? null : message;
        }

        public Message GetNextSelectedMessage()
        {
            var folder = GetCurrentFolder();

            var messageID = _wlmailApiCore.GetNextSelectedMessageID();

            var message = folder.GetMessage(messageID);

            ReleaseComObject(folder);

            return message.GetID() == -1 ? null : message;
        }

        public Folder GetCurrentFolder()
        {
            var folderId = (ulong)_wlmailApiCore.GetSelectedFolderID();
            return _folderManager.GetFolder(folderId);
        }

        public bool IsFromQuickViews(Folder folder)
        {
            var rootFolder = _folderManager.GetFolder((int)tagSPECIALFOLDERID.NKT_FOLDER_ROOT);
            var rootFolderId = rootFolder.GetID();
            ReleaseComObject(rootFolder);
            rootFolder = null;

            var childrenIds = GetChildrenIds((int)rootFolderId);

            var quickViewsFoldersIds = new List<int>();

            foreach (var childId in childrenIds)
            {
                var child = _folderManager.GetFolder((ulong)childId);
                if (child.GetID() == QuickViewsFolderID)
                {
                    quickViewsFoldersIds = GetChildrenIds(childId);
                    ReleaseComObject(child);
                    break;
                }
                ReleaseComObject(child);
            }

            return quickViewsFoldersIds.Contains((int)folder.GetID());
        }

        private List<int> GetChildrenIds(int folderId)
        {
            var folder = _folderManager.GetFolder((ulong)folderId);

            var childFolder = folder.GetFirstChild();

            var childrenIds = new List<int>();

            while (childFolder != null)
            {
                childrenIds.Add((int)childFolder.GetID());
                ReleaseComObject(childFolder);
                childFolder = folder.GetNextChild();
            }

            childFolder = null;

            ReleaseComObject(folder);
            folder = null;

            return childrenIds;
        }

        public int CommitIfNotInQuickViews(Message msg)
        {
            var folder = _folderManager.GetFolder(msg.GetFolderID());

            if (IsFromQuickViews(folder))
            {
                ShowMsgBox("You can't save nor modify a message " +
                           "in a Quick Views folder.\n");
                return 0;
            }

            ReleaseComObject(folder);
            folder = null;

            return msg.Commit();

        }

        public int MoveIfNotInQuickViews(Message msg, int destFolderId)
        {
            var folder = _folderManager.GetFolder(msg.GetFolderID());

            if (IsFromQuickViews(folder))
            {
                ShowMsgBox("You can't move a message you selected " +
                            "from a Quick Views folder.\n");
                return 0;
            }

            ReleaseComObject(folder);
            folder = null;

            return _folderManager.MoveMessage(msg.GetFolderID(), (ulong)destFolderId, msg.GetID());
        }

        public void CleanWLMailApiReferences()
        {
            _wlmailApiCore = null;
            _folderManager = null;
            _accountManager = null;
        }

        public int ReleaseComObject(object obj)
        {
            var remainingRefs = -1;

            if (obj != null)
            {
                remainingRefs = Marshal.ReleaseComObject(obj);
                obj = null;
            }

            return remainingRefs;
        }

        public class RegexUtils
        {
            static bool _invalid;

            public static bool IsValidEmail(string strIn)
            {
                _invalid = false;
                if (String.IsNullOrEmpty(strIn))
                    return false;

                // Use IdnMapping class to convert Unicode domain names.
                strIn = Regex.Replace(strIn, @"(@)(.+)$", DomainMapper);
                if (_invalid)
                    return false;

                // Return true if strIn is in valid e-mail format.
                return Regex.IsMatch(strIn,
                       @"^(?("")(""[^""]+?""@)|(([0-9a-z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-z])@))" +
                       @"(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-z][-\w]*[0-9a-z]*\.)+[a-z0-9]{2,17}))$",
                       RegexOptions.IgnoreCase);
            }

            private static string DomainMapper(Match match)
            {
                // IdnMapping class with default property values.
                var idn = new IdnMapping();

                string domainName = match.Groups[2].Value;
                try
                {
                    domainName = idn.GetAscii(domainName);
                }
                catch (ArgumentException)
                {
                    _invalid = true;
                }
                return match.Groups[1].Value + domainName;
            }
        }

    }
}
