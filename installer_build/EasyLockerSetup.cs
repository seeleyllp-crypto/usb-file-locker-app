using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new SetupWindow());
    }
}

internal sealed class SetupWindow : Form
{
    private static readonly string InstallDirectory =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs", "USB File Locker");
    private static readonly string InstalledApp = Path.Combine(InstallDirectory, "USB File Locker.exe");
    private static readonly string SafetyInstallDirectory =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs", "PC Safety Check");
    private static readonly string SafetyApp = Path.Combine(SafetyInstallDirectory, "PC Safety Check.exe");
    private static readonly string SetupPayloadRoot =
        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Privacy Safety Setup Files");
    private readonly Button installButton;
    private readonly Button removeButton;
    private readonly Label status;

    public SetupWindow()
    {
        Text = "Privacy and PC Safety Setup";
        ClientSize = new Size(620, 470);
        MinimumSize = new Size(620, 470);
        MaximumSize = new Size(620, 470);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(246, 247, 249);
        Font = new Font("Segoe UI", 10F);

        Label title = new Label
        {
            Text = "Privacy and PC Safety",
            Font = new Font("Segoe UI", 25F, FontStyle.Bold),
            ForeColor = Color.FromArgb(20, 24, 32),
            AutoSize = true,
            Location = new Point(38, 28)
        };
        Controls.Add(title);

        Label subtitle = new Label
        {
            Text = "Easy file privacy and Microsoft Defender safety checks.",
            Font = new Font("Segoe UI", 11F),
            ForeColor = Color.FromArgb(82, 88, 101),
            AutoSize = true,
            Location = new Point(42, 80)
        };
        Controls.Add(subtitle);

        AddStep(1, "Plug in the USB drive you want to use as the key.", 126);
        AddStep(2, "Install the file locker and PC Safety Check.", 190);
        AddStep(3, "Open USB File Locker, click CREATE MASTER USB KEY,\nand save the new key on the USB drive.", 254);

        installButton = new Button
        {
            Text = AppsInstalled() ? "REINSTALL / REPAIR" : "INSTALL BOTH APPS",
            Font = new Font("Segoe UI", 11F, FontStyle.Bold),
            ForeColor = Color.FromArgb(10, 24, 15),
            BackColor = Color.FromArgb(55, 222, 119),
            FlatStyle = FlatStyle.Flat,
            Size = new Size(330, 52),
            Location = new Point(42, 354),
            Cursor = Cursors.Hand
        };
        installButton.FlatAppearance.BorderSize = 0;
        installButton.Click += InstallClicked;
        Controls.Add(installButton);

        removeButton = new Button
        {
            Text = "REMOVE",
            Font = new Font("Segoe UI", 10F, FontStyle.Bold),
            ForeColor = Color.FromArgb(42, 47, 57),
            BackColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(150, 52),
            Location = new Point(390, 354),
            Enabled = AnyAppInstalled(),
            Cursor = Cursors.Hand
        };
        removeButton.FlatAppearance.BorderColor = Color.FromArgb(190, 194, 203);
        removeButton.Click += RemoveClicked;
        Controls.Add(removeButton);

        status = new Label
        {
            Text = AppsInstalled()
                ? "Both privacy and safety apps are installed. Repair or remove them here."
                : "Ready to install both apps. No administrator password is needed.",
            Font = new Font("Segoe UI", 9F),
            ForeColor = Color.FromArgb(82, 88, 101),
            AutoSize = false,
            Size = new Size(520, 30),
            Location = new Point(42, 421)
        };
        Controls.Add(status);
    }

    private void AddStep(int number, string text, int y)
    {
        Label badge = new Label
        {
            Text = number.ToString(),
            TextAlign = ContentAlignment.MiddleCenter,
            Font = new Font("Segoe UI", 11F, FontStyle.Bold),
            ForeColor = Color.White,
            BackColor = Color.FromArgb(38, 44, 56),
            Size = new Size(38, 38),
            Location = new Point(42, y)
        };
        Controls.Add(badge);

        Label copy = new Label
        {
            Text = text,
            Font = new Font("Segoe UI", 11F),
            ForeColor = Color.FromArgb(28, 33, 43),
            AutoSize = false,
            Size = new Size(470, 56),
            Location = new Point(98, y + 6)
        };
        Controls.Add(copy);
    }

    private void InstallClicked(object sender, EventArgs e)
    {
        SetBusy(true, "Installing...");
        try
        {
            foreach (Process process in Process.GetProcessesByName("USB File Locker"))
            {
                try { process.CloseMainWindow(); } catch { }
            }
            foreach (Process process in Process.GetProcessesByName("PC Safety Check"))
            {
                try { process.CloseMainWindow(); } catch { }
            }
            if (Directory.Exists(InstallDirectory))
                Directory.Delete(InstallDirectory, true);
            if (Directory.Exists(SafetyInstallDirectory))
                Directory.Delete(SafetyInstallDirectory, true);
            CopyDirectory(Path.Combine(SetupPayloadRoot, "USB File Locker"), InstallDirectory);
            CopyDirectory(Path.Combine(SetupPayloadRoot, "PC Safety Check"), SafetyInstallDirectory);

            CreateShortcut(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    "USB File Locker.lnk"),
                InstalledApp);

            string startMenuFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
                "Programs", "USB File Locker");
            Directory.CreateDirectory(startMenuFolder);
            CreateShortcut(Path.Combine(startMenuFolder, "USB File Locker.lnk"), InstalledApp);
            CreateShortcut(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    "PC Safety Check.lnk"),
                SafetyApp);
            CreateShortcut(Path.Combine(startMenuFolder, "PC Safety Check.lnk"), SafetyApp);
            RegisterLockedFiles();

            installButton.Text = "REINSTALL / REPAIR";
            removeButton.Enabled = true;
            status.Text = "Both apps are installed. Opening them now...";
            MessageBox.Show(
                "USB File Locker and PC Safety Check are installed.\n\nNext: open USB File Locker, click CREATE MASTER USB KEY, and save the key on the USB drive.\n\nNever lose the USB key. Locked files cannot be recovered without it.",
                "Installation complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
            Process.Start(new ProcessStartInfo(InstalledApp) { UseShellExecute = true });
            Process.Start(new ProcessStartInfo(SafetyApp) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            status.Text = "Installation did not finish.";
            MessageBox.Show("Could not install the privacy and safety apps.\n\n" + ex.Message,
                "Installation problem", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            SetBusy(false, status.Text);
        }
    }

    private void RemoveClicked(object sender, EventArgs e)
    {
        if (MessageBox.Show(
                "Remove USB File Locker, PC Safety Check, and their shortcuts?\n\nLocked files and USB keys will NOT be deleted.",
                "Remove privacy and safety apps", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
            return;

        SetBusy(true, "Removing...");
        try
        {
            foreach (Process process in Process.GetProcessesByName("USB File Locker"))
            {
                try { process.CloseMainWindow(); } catch { }
            }
            foreach (Process process in Process.GetProcessesByName("PC Safety Check"))
            {
                try { process.CloseMainWindow(); } catch { }
            }

            DeleteIfPresent(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                "USB File Locker.lnk"));
            DeleteIfPresent(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                "PC Safety Check.lnk"));
            string startMenuFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
                "Programs", "USB File Locker");
            if (Directory.Exists(startMenuFolder))
                Directory.Delete(startMenuFolder, true);
            UnregisterLockedFiles();
            if (Directory.Exists(InstallDirectory))
                Directory.Delete(InstallDirectory, true);
            if (Directory.Exists(SafetyInstallDirectory))
                Directory.Delete(SafetyInstallDirectory, true);

            installButton.Text = "INSTALL BOTH APPS";
            removeButton.Enabled = false;
            status.Text = "Removed. Locked files and USB keys were left untouched.";
            MessageBox.Show(status.Text, "Removed", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            status.Text = "Removal did not finish.";
            MessageBox.Show("Could not remove everything.\n\nClose USB File Locker and try again.\n\n" + ex.Message,
                "Removal problem", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            SetBusy(false, status.Text);
        }
    }

    private void SetBusy(bool busy, string message)
    {
        installButton.Enabled = !busy;
            removeButton.Enabled = !busy && AnyAppInstalled();
        status.Text = message;
        UseWaitCursor = busy;
        Refresh();
    }

    private static void CreateShortcut(string shortcutPath, string targetPath)
    {
        Type shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType == null)
            throw new InvalidOperationException("Windows could not create the desktop shortcut.");
        object shell = Activator.CreateInstance(shellType);
        object shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod,
            null, shell, new object[] { shortcutPath });
        Type shortcutType = shortcut.GetType();
        shortcutType.InvokeMember("TargetPath", BindingFlags.SetProperty,
            null, shortcut, new object[] { targetPath });
        shortcutType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty,
            null, shortcut, new object[] { Path.GetDirectoryName(targetPath) });
        shortcutType.InvokeMember("Description", BindingFlags.SetProperty,
            null, shortcut, new object[] { "Lock and unlock files with a master USB key" });
        shortcutType.InvokeMember("Save", BindingFlags.InvokeMethod,
            null, shortcut, null);
        Marshal.FinalReleaseComObject(shortcut);
        Marshal.FinalReleaseComObject(shell);
    }

    private static void RegisterLockedFiles()
    {
        const string progId = "USBFileLocker.LockedFile";
        using (RegistryKey classes = Registry.CurrentUser.CreateSubKey(@"Software\Classes"))
        {
            foreach (string extension in new[] { ".locked", ".lookeed" })
                using (RegistryKey key = classes.CreateSubKey(extension))
                    key.SetValue("", progId);
            using (RegistryKey key = classes.CreateSubKey(progId))
                key.SetValue("", "USB File Locker Locked File");
            using (RegistryKey key = classes.CreateSubKey(progId + @"\DefaultIcon"))
                key.SetValue("", "\"" + InstalledApp + "\",0");
            using (RegistryKey key = classes.CreateSubKey(progId + @"\shell\open\command"))
                key.SetValue("", "\"" + InstalledApp + "\" --unlock \"%1\"");
        }
        SHChangeNotify(0x08000000, 0, IntPtr.Zero, IntPtr.Zero);
    }

    private static void UnregisterLockedFiles()
    {
        using (RegistryKey classes = Registry.CurrentUser.OpenSubKey(
                   @"Software\Classes", true))
        {
            if (classes == null) return;
            foreach (string name in new[] { ".locked", ".lookeed", "USBFileLocker.LockedFile" })
            {
                try { classes.DeleteSubKeyTree(name, false); } catch { }
            }
        }
        SHChangeNotify(0x08000000, 0, IntPtr.Zero, IntPtr.Zero);
    }

    private static void DeleteIfPresent(string path)
    {
        if (File.Exists(path))
            File.Delete(path);
    }

    private static bool AppsInstalled()
    {
        return File.Exists(InstalledApp) && File.Exists(SafetyApp);
    }

    private static bool AnyAppInstalled()
    {
        return File.Exists(InstalledApp) || File.Exists(SafetyApp);
    }

    private static void CopyDirectory(string source, string destination)
    {
        if (!Directory.Exists(source))
            throw new DirectoryNotFoundException(
                "The setup files are missing. Keep this installer beside the Privacy Safety Setup Files folder.");
        Directory.CreateDirectory(destination);
        foreach (string directory in Directory.GetDirectories(source, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(directory.Replace(source, destination));
        foreach (string file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
            File.Copy(file, file.Replace(source, destination), true);
    }

    [DllImport("shell32.dll")]
    private static extern void SHChangeNotify(uint eventId, uint flags, IntPtr item1, IntPtr item2);
}
