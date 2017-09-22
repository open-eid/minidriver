#powershell -ExecutionPolicy ByPass -File buildmsi.ps1 -msiversion 3.12.0.0
param(
   [string]$candle = "$env:WIX\bin\candle.exe",
   [string]$light = "$env:WIX\bin\light.exe",
   [string]$msiversion = "3.12.0.77",
   [string]$sign = $null
)

$cwd = Split-Path $MyInvocation.MyCommand.Path
$shell = new-object -com shell.application
mkdir -Force -Path "minidriver\W10"
mkdir -Force -Path "minidriver\PreW10"
foreach($item in $shell.NameSpace("$cwd\esteidcm_$($msiversion)-W10.zip").items()) {
    $shell.Namespace("$cwd\minidriver\W10").CopyHere($item,0x14)
}
foreach($item in $shell.NameSpace("$cwd\esteidcm_$($msiversion)-PreW10.zip").items()) {
    $shell.Namespace("$cwd\minidriver\PreW10").CopyHere($item,0x14)
}
foreach($platform in @("x86", "x64")) {
    & $candle -nologo minidriver.wxs "-dPlatform=$platform" "-dMSI_VERSION=$msiversion" `
        -arch $platform -ext WixDifxAppExtension
    & $light -nologo -out "minidriver-$msiversion.$platform.msi" -ext WixUIExtension -ext WixDifxAppExtension `
        "-dWixUILicenseRtf=LICENSE.rtf" "-dWixUIDialogBmp=dlgbmp.bmp" "-dWixUIBannerBmp=banner.bmp" `
        "$env:WIX\bin\difxapp_$platform.wixlib" minidriver.wixobj
    if($sign) {
        & signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
            /t http://timestamp.verisign.com/scripts/timstamp.dll "minidriver-$msiversion.$platform.msi"
    }
}
