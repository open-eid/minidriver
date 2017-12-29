param(
  [string]$buildnr = "0",
  [string]$version = "3.12.1.$buildnr",
  [string]$date = $(Get-Date -format "MM\/dd\/yyyy"),
  [string]$target = "Package",
  [string]$driver = "$target\minidriver",
  [string]$msbuild = "C:\Program Files (x86)\MSBuild\12.0\Bin\MSBuild.exe",
  [string]$stampinf = "C:\Program Files (x86)\Windows Kits\10\bin\x64\stampinf.exe",
  [string]$Inf2Cat = "C:\Program Files (x86)\Windows Kits\10\bin\x86\Inf2Cat.exe",
  [string]$7zip = "C:\Program Files\7-Zip\7z.exe",
  [string]$sign = $null
)

function makecab($dir, $cab)
{
    $ddf = ".OPTION EXPLICIT
.Set CabinetNameTemplate=$cab
.Set DiskDirectory1=.
.Set CompressionType=MSZIP
.Set Cabinet=on
.Set Compress=on
.Set CabinetFileCountThreshold=0
.Set FolderFileCountThreshold=0
.Set FolderSizeThreshold=0
.Set MaxCabinetSize=0
.Set MaxDiskFileCount=0
.Set MaxDiskSize=0
"
    $dirfullname = (get-item $dir).fullname
    $ddfpath = ($env:TEMP+"\temp.ddf")
    $ddf += (ls -recurse $dir | ? {!$_.psiscontainer}|select -expand fullname|%{'"'+$_+'" "'+$_.SubString($dirfullname.length+1)+'"'}) -join "`r`n"
    $ddf
    $ddf | Out-File -encoding UTF8 $ddfpath
    & makecab.exe "/F" "$ddfpath"
    rm $ddfpath
    rm setup.inf
    rm setup.rpt
}

& $msbuild /nologo /verbosity:quiet "/p:Configuration=Release;Platform=Win32;BUILD_NUMBER=$buildnr" esteidcm.sln
& $msbuild /nologo /verbosity:quiet "/p:Configuration=Release;Platform=X64;BUILD_NUMBER=$buildnr" esteidcm.sln

Remove-Item $driver -Force -Recurse > $null
New-Item -ItemType directory -Path "$driver" > $null
Copy-Item "Release\esteidcm.dll" "$driver\esteidcm_32.dll"
Copy-Item "Release\esteidcm.pdb" "$driver\esteidcm_32.pdb"
Copy-Item "x64\Release\esteidcm.dll" "$driver\esteidcm_64.dll"
Copy-Item "x64\Release\esteidcm.pdb" "$driver\esteidcm_64.pdb"
Copy-Item "Win7Release\atrfiltr.sys" "$driver\atrfiltr_32.sys"
Copy-Item "x64\Win7Release\atrfiltr.sys" "$driver\atrfiltr_64.sys"
Copy-Item "esteidcm.inf" "$driver\esteidcm.inf"

& $stampinf -f "$driver\esteidcm.inf" -d $date -v $version
& $Inf2Cat "/driver:$driver" "/verbose" "/os:7_X86,7_X64,6_3_X86,6_3_X64,Server2008R2_X64,Server8_X64,Server6_3_X64,10_X86,10_X64,Server10_X64"
makecab $target "esteidcm_$version.cab"
if($sign) {
  & signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
    /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp /td SHA256 "esteidcm_$version.cab"
}

& $7zip "a" "-tzip" "-r" "esteidcm.$version.zip", "$target" > $null
