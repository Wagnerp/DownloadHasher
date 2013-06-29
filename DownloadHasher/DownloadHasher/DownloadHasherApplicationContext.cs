/*
Copyright (c) 2013 "Zachary Graber"

This file is part of DownloadHasher.

Veil is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DownloadHasher
{
   //http://www.codeproject.com/Articles/58740/FileSystemWatcher-Pure-Chaos-Part-1-of-2?msg=4512485#xx4512485xx
    class DownloadHasherApplicationContext : ApplicationContext
    {
        private NotifyIcon trayIcon;
        private ContextMenu trayMenu;
        private FileSystemWatcher watcher;
        string logFileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), ".file_hashes.txt");
        string previousFile = ""; // previous file that was hashed - used because the FileSystemWatcher throws multiple events per file
        DateTime previousTime; // previous time a file was hashed - used because the FileSystemWatcher throws multiple events per file
        bool notifyToggle = true; // turn the balloon tip on or off
        const int TIMEOUT = 5000; // timeout for trying to read a file

        public DownloadHasherApplicationContext()
        {
            // construct and setup
            InitializeNotifyIcon();
            InitializeWatcher();
        }

        private void InitializeWatcher()
        {
            // setup the file system watcher
            watcher = new FileSystemWatcher();
            watcher.IncludeSubdirectories = true;
            watcher.NotifyFilter = NotifyFilters.FileName| NotifyFilters.LastWrite;

            watcher.Changed += new System.IO.FileSystemEventHandler(this.FileSystemEventHandler);
            watcher.Created += new System.IO.FileSystemEventHandler(this.FileSystemEventHandler);

            // monitor the downloads folder
            watcher.Path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            watcher.EnableRaisingEvents = true;
        }

        private void InitializeNotifyIcon()
        {
            // create tray menu options
            trayMenu = new ContextMenu();
            trayMenu.MenuItems.Add("Open Log", BalloonTipClicked);
            trayMenu.MenuItems.Add("Toggle Notifications", ToggleNotifications);
            trayMenu.MenuItems.Add("Exit", OnExit);
            
            // create the tray icon and subscribe to events
            trayIcon = new NotifyIcon();
            trayIcon.BalloonTipClicked += new EventHandler(this.BalloonTipClicked);
            trayIcon.DoubleClick += new EventHandler(this.NotifyIconDoubleClick);
            trayIcon.Text = "Hasher";
            trayIcon.Icon = new Icon("#again5.ico", 40, 40);

            trayIcon.ContextMenu = trayMenu;
            trayIcon.Visible = true;
        }

        private void FileSystemEventHandler(object sender, System.IO.FileSystemEventArgs e)
        {
            // only interested in file changes
            if (Directory.Exists(e.FullPath)) return;
            // ignore list - these are tmp files that cause problems
            List<string> ignoreExtension = new List<string>(new string[] { ".tmp",".crdownload"});
            if (ignoreExtension.FindAll(s => s.IndexOf(Path.GetExtension(e.FullPath), StringComparison.OrdinalIgnoreCase) >= 0).Count > 0) return;
            if (!(e.ChangeType == WatcherChangeTypes.Changed || e.ChangeType == WatcherChangeTypes.Created)) return;

            DateTime current = DateTime.Now;
            TimeSpan span = current.Subtract(previousTime);

            // eat if it occured with the timeout and it was the same file
            if (span.TotalMilliseconds < TIMEOUT && previousFile.Equals(e.FullPath, StringComparison.OrdinalIgnoreCase)) return;

            previousTime = current;
            previousFile = e.FullPath;

            // get the hashes (md5 and sha1)
            List<string> hashes = GetFileHashes(e.FullPath);

            // the number of hashes should equal the number of algs
            if (hashes.Count != 2) return;

            string logtxt = string.Format("{0}  --  {1}\r\nMD5:        {2}\r\nSHA1:       {3}\r\n\r\n", DateTime.Now.ToString("dddd MM/dd/yyyy hh:mm:ss:FFF tt"), e.FullPath, hashes[0], hashes[1]);
            UpdateLogFile(logtxt);

            if (notifyToggle) DisplayBalloonTip(e.FullPath, string.Format("SHA1:  {0}\r\nMD5:   {1}", hashes[1], hashes[0]));
        }

        private  void DisplayBalloonTip(string title, string message)
        {
            // maybe add in a way to limit the time span between messages
            trayIcon.ShowBalloonTip(2500, title, message, new ToolTipIcon());
        }

        private void BalloonTipClicked(object sender, EventArgs e)
        {
            if (File.Exists(logFileName)) System.Diagnostics.Process.Start(logFileName);
        }

        private void NotifyIconDoubleClick(object sender, EventArgs e)
        {
            BalloonTipClicked(sender, e);
        }

        private List<string> GetFileHashes(string filename)
        {
            bool loop = true;
            List<string> hashes = new List<string>();
            DateTime t1 = DateTime.Now;
            // loop until you successfully read the hashes
            while (loop)
            {
                // time out after 5 seconds
                DateTime t2 = DateTime.Now;
                TimeSpan span = t2.Subtract(t1);
                // if the file no longer exists then exit
                if (!File.Exists(filename)) return hashes;
                // try to open the file - this will fail until all systems release it
                try
                {
                    using (var stream = new FileStream(filename, FileMode.Open, FileAccess.Read))
                    {
                        Hash h = new Hash();
                        // can change these to any of the implemented hashes
                        string md5 = h.GetFileHash(Hash.HashAlg.MD5, stream);
                        stream.Seek(0, SeekOrigin.Begin);
                        string ripemd160 = h.GetFileHash(Hash.HashAlg.RIPEMD160, stream);
                        stream.Seek(0, SeekOrigin.Begin);
                        string sha1 = h.GetFileHash(Hash.HashAlg.SHA1, stream);
                        /*
                        stream.Seek(0, SeekOrigin.Begin);
                        string sha256 = h.GetFileHash(Hash.HashAlg.SHA256, stream);
                        stream.Seek(0, SeekOrigin.Begin);
                        string sha384 = h.GetFileHash(Hash.HashAlg.SHA384, stream);
                        stream.Seek(0, SeekOrigin.Begin);
                        string sha512 = h.GetFileHash(Hash.HashAlg.SHA512, stream);
                        */
                        hashes.AddRange(new string[] { md5,  sha1,});
                    }
                    // has finished successfully
                    loop = false;
                }
                catch { }
                System.Threading.Thread.Sleep(100);
            }
            return hashes;
        }

        private void UpdateLogFile(string log)
        {
            string tempFileName = GetTempFilePathWithExtension("txt");
            

            if (File.Exists(logFileName)) File.SetAttributes(logFileName, FileAttributes.Normal);

            using (var tempStream = new FileStream(tempFileName, FileMode.Create,FileAccess.ReadWrite))
            {
                // write the new data to the temp file
                tempStream.Write(Encoding.Unicode.GetBytes(log), 0, Encoding.Unicode.GetByteCount(log));

                // copy the old data from the log file to the temp file chunk by chunk
                int chunk_size = 1048576;
                using (var logStream = new FileStream(logFileName, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    byte[] buffer;

                    long numBytesToRead = logStream.Length;
                    int numBytesRead = 0;
                    // set the buffer size to 1 MB unless the size of the file is smaller
                    int buf_size = (numBytesToRead < chunk_size) ? (int)numBytesToRead : chunk_size;

                    while (numBytesToRead > 0)
                    {
                        int n = 0;
                        buffer = new byte[buf_size];
                        n = logStream.Read(buffer, numBytesRead, buf_size);

                        // correct the size of the buffer with the actual size read
                        if (n < buffer.Length)
                        {
                            byte[] temp = new byte[n];
                            Array.Copy(buffer, temp, n);
                            buffer = new byte[n];
                            buffer = temp;
                        }

                        numBytesRead += n;
                        numBytesToRead -= n;
                        tempStream.Write(buffer, 0, buffer.Length);
                    }
                }
            }
            File.Copy(tempFileName, logFileName, true);
            File.Delete(tempFileName);

            File.SetAttributes(logFileName, File.GetAttributes(logFileName) | FileAttributes.Hidden);
        }

        public static string GetTempFilePathWithExtension(string extension)
        {
            var path = Path.GetTempPath();
            var fileName = Guid.NewGuid().ToString();
            return Path.ChangeExtension(Path.Combine(path, fileName),extension);
        }

        private void OnExit(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void ToggleNotifications(object sender, EventArgs e)
        {
            notifyToggle = !notifyToggle;
        }

        protected override void Dispose(bool isDisposing)
        {
            if (isDisposing)
            {
                // Release the icon resource.
                trayIcon.Dispose();
            }

            base.Dispose(isDisposing);
        }
    }
}
