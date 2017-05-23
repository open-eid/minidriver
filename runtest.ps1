param(
  [string]$target = "C:\SmartCardMinidriverTest",
  [string]$7zip = "C:\Program Files\7-Zip\7z.exe"
)

New-Item -ItemType directory -Path $target > $null
Copy-Item "esteidcm.inf" "$target\esteidcm.inf"
Copy-Item "cmck_config.xml" "$target\cmck_config.xml"
Push-Location -Path $target
& "C:\Program Files (x86)\Microsoft Driver Test Manager\Tests\x86fre\NTTest\dstest\security\core\bin\credentials\smartcard\cmck.exe" certify
Pop-Location
& $7zip "a" "-tzip" "-r" "esteidcm_cmck.X86.zip" "$target\*" #> $null
Push-Location -Path $target
& "C:\Program Files (x86)\Microsoft Driver Test Manager\Tests\amd64fre\NTTest\dstest\security\core\bin\credentials\smartcard\cmck.exe" certify
Pop-Location
& $7zip "a" "-tzip" "-r" "esteidcm_cmck.X64.zip" "$target\*" > $null
