#powershell -ExecutionPolicy ByPass -File buildmsi.ps1 -msiversion 3.12.0.0
param(
   [string]$candle = "$env:WIX\bin\candle.exe",
   [string]$light = "$env:WIX\bin\light.exe",
   [string]$msiversion = "3.11.0.1175",
   [string]$sign = $null
)

$cwd = Split-Path $MyInvocation.MyCommand.Path
$shell = new-object -com shell.application
foreach($platform in @("x86", "x64")) {
    foreach($version in @("7", "8", "8.1")) {
        mkdir -Force -Path "minidriver\$version$platform"
        foreach($item in $shell.NameSpace("$cwd\esteidcm.$($msiversion)_win$version$platform.zip").items()) {
            $shell.Namespace("$cwd\minidriver\$version$platform").CopyHere($item,0x14)
        }
    }
    foreach($version in @("10")) {
        mkdir -Force -Path "minidriver\$version$platform"
        & expand.exe .\esteidcm.$($msiversion)_win$version$platform.cab -F:* "minidriver\$version$platform"
    }
    & $candle -nologo minidriver.wxs "-dPlatform=$platform" "-dMSI_VERSION=$msiversion" `
        -arch $platform -ext WixDifxAppExtension
    & $light -nologo -out "minidriver_$msiversion.$platform.msi" -ext WixUIExtension -ext WixDifxAppExtension `
        "$env:WIX\bin\difxapp_$platform.wixlib" minidriver.wixobj
    if($sign) {
        & signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
            /t http://timestamp.verisign.com/scripts/timstamp.dll "minidriver_$msiversion.$platform.msi"
    }
}
