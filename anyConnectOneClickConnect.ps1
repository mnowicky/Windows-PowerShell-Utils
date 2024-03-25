<#
========================================================================
-- Author                 : MNOWICKY
-- Create date            : 26-06-2018
-- Description            : AnyConnect Single Click Login
===========================================================================
#>

Set-ExecutionPolicy -ExecutionPolicy Bypass
TRY{
Set-ExecutionPolicy -ExecutionPolicy Bypass
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::
GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}

Set-ExecutionPolicy -ExecutionPolicy Bypass

$vpnuiAbsolutePath = 'C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility 
Client\vpnui.exe' # Check the location CISCO vpnui.exe presence must and should.
$ServerIpAddress="VPN.DON.COM"
$UserName=""
$Password=""  #Here you can secure ur password by using encryption process. Or just use plaintext.

Start-Process -FilePath $vpnuiAbsolutePath

$pinvokes = @'

using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Text;
public class Program
{
private delegate bool EnumWindowProc(IntPtr hWnd, IntPtr parameter);
// Get a handle to an application window.
[DllImport("USER32.DLL", CharSet = CharSet.Unicode)]
public static extern IntPtr FindWindow(string lpClassName,
string lpWindowName);
[DllImport("user32.dll", EntryPoint = "FindWindow", SetLastError = true)]
private static extern IntPtr FindWindowByCaption(IntPtr zeroOnly, string lpWindowName);
[DllImport("user32.dll", EntryPoint = "GetWindowText", CharSet = CharSet.Auto)]
private static extern IntPtr GetWindowCaption(IntPtr hwnd, StringBuilder lpString, int maxCount);
[return: MarshalAs(UnmanagedType.Bool)]
[DllImport("user32.dll", SetLastError = true)]
private static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
[DllImport("User32.dll", SetLastError = true, CharSet = CharSet.Auto)]
static extern long GetWindowText(IntPtr hwnd, StringBuilder lpString, long cch);
// Activate an application window.
[DllImport("USER32.DLL")]
public static extern bool SetForegroundWindow(IntPtr hWnd);
[DllImport("user32")]
[return: MarshalAs(UnmanagedType.Bool)]
private static extern bool EnumChildWindows(IntPtr window, EnumWindowProc callback, IntPtr i);
public static int disconnectValue = 0;

        public static void ClickButtonLabeledYes()
        {
            try
            {
                IntPtr focusWindow = FindWindow
                         ("SetFocus", "Cisco AnyConnect Secure Mobility Client");
                var windowCaption = FindWindowByCaption(IntPtr.Zero, 
                                     "Cisco AnyConnect Secure Mobility Client");
                if (windowCaption.ToString().Length >= 2)
                {
                    SetForegroundWindow(focusWindow);
                    EnumChildWindows(windowCaption, EnumChildWindowsCallback, IntPtr.Zero);
                }
            }
            catch (Exception e)
            {
                // new LogEntry(": " + e.ToString());
            }
        }

        public static bool EnumChildWindowsCallback(IntPtr handle, IntPtr pointer)
        {
            const uint WMLBUTTONDOWN = 0x0201;

            const uint WMLBUTTONUP = 0x0202;

            var sb = new StringBuilder(256);
            // Get the control's text.

            GetWindowCaption(handle, sb, 256);

            var text = sb.ToString();
            if (text.ToString().Equals("Connect", StringComparison.InvariantCultureIgnoreCase))
            {
                PostMessage(handle, WMLBUTTONDOWN, IntPtr.Zero, IntPtr.Zero);
                PostMessage(handle, WMLBUTTONUP, IntPtr.Zero, IntPtr.Zero);
            }
            else if (text.ToString().Equals
                       ("Disconnect", StringComparison.InvariantCultureIgnoreCase)) 
            {
                disconnectValue = 1;
            }

            return true;
        }

        public static void SecondWindowClick(string Password)
        {
            try
            {
                IntPtr focusWindow = FindWindow("SetFocus", "Cisco AnyConnect | 
                YOUR DOMAIN NAME"); // Enter your org domain name like shown on CISCO window Header 
                var windowCaption = FindWindowByCaption(IntPtr.Zero, "Cisco AnyConnect | 
                YOUR DOMAIN NAME"); // Enter your org domain name like shown on CISCO window Header 
                if (windowCaption.ToString().Length >= 2)
                {
                    SetForegroundWindow(focusWindow);
                    SendKeys.SendWait(Password);
                    EnumChildWindows(windowCaption, SecondWindowClickCallback, IntPtr.Zero);
                }
            }
            catch (Exception e)
            {
                // new LogEntry(": " + e.ToString());
            }
        }

        public static bool SecondWindowClickCallback(IntPtr handle, IntPtr pointer)
        {
            const uint WMLBUTTONDOWN = 0x0201;
            const uint WMLBUTTONUP = 0x0202;

            var sb = new StringBuilder(256);
            GetWindowCaption(handle, sb, 256);
            var text = sb.ToString();
            if (text.ToString().EndsWith("OK", StringComparison.InvariantCultureIgnoreCase))
            {
                PostMessage(handle, WMLBUTTONDOWN, IntPtr.Zero, IntPtr.Zero);
                PostMessage(handle, WMLBUTTONUP, IntPtr.Zero, IntPtr.Zero);
            }
            return true;
        }

        public static void ThirdWindowClick()
        {
            try
            {
                IntPtr focusWindow = FindWindow("SetFocus", "Cisco AnyConnect");
                var windowCaption = FindWindowByCaption(IntPtr.Zero, "Cisco AnyConnect");
                if (windowCaption.ToString().Length >= 2)
                {
                    SetForegroundWindow(focusWindow);
                    EnumChildWindows(windowCaption, ThirdWindowClickCallback, IntPtr.Zero);
                }
            }
            catch (Exception e)
            {
                // new LogEntry(": " + e.ToString());
            }
        }

        public static bool ThirdWindowClickCallback(IntPtr handle, IntPtr pointer)
        {
            const uint WMLBUTTONDOWN = 0x0201;
            const uint WMLBUTTONUP = 0x0202;

            var sb = new StringBuilder(256);
            GetWindowCaption(handle, sb, 256);
            var text = sb.ToString();
            if (text.ToString().EndsWith("Accept", StringComparison.InvariantCultureIgnoreCase))
            {
                PostMessage(handle, WMLBUTTONDOWN, IntPtr.Zero, IntPtr.Zero);
                PostMessage(handle, WMLBUTTONUP, IntPtr.Zero, IntPtr.Zero);
            }
            return true;
        }

}
'@

[Reflection.Assembly]::LoadWithPartialName("System")

[Reflection.Assembly]::LoadWithPartialName("System.Runtime.InteropServices")

[Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

[Reflection.Assembly]::LoadFile("C:\Program Files 
 (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.0\mscorlib.dll") # Check the location library presence must and should.

$refs = @("System","System.Runtime.InteropServices","System.Windows.Forms")

Add-Type -TypeDefinition $pinvokes -ReferencedAssemblies $refs -IgnoreWarnings

Start-Sleep -s 7 # SET TIME interval based on your internet and RAM speed
[Program]::ClickButtonLabeledYes()

$testvarible = [Program]::disconnectValue

If ($testvarible  -eq '0'){
Start-Sleep -s 7  # SET TIME interval based on your internet and RAM speed
[program]::SecondWindowClick($Password)

Start-Sleep -s 7  # SET TIME interval based on your internet and RAM speed
[program]::ThirdWindowClick()

Start-Sleep -s 7 # SET TIME interval based on your internet and RAM speed
}
Else {
Start-Sleep -s 1
}
 cmdkey /generic:TERMSRV/$ServerIpAddress /user:$UserName /pass:$Password
 mstsc /v:$ServerIpAddress
}
catch{

$ErrorMessage = $_.Exception.Message
$FailedItem = $_.Exception.ItemName

Write-Output($ErrorMessage)
Write-Output($FailedItem)
Start-Sleep -s 10
}