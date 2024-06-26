# EstEID Smart Card MiniDriver

![European Regional Development Fund](https://github.com/open-eid/DigiDoc4-Client/blob/master/client/images/EL_Regionaalarengu_Fond.png "European Regional Development Fund - DO NOT REMOVE THIS IMAGE BEFORE 05.03.2020")

**NB! Please note that the active development and management of the EstEID Smart Card MiniDriver has ended as all EstEID Smart Cards are expired. More information is available here: https://www.id.ee/en/article/id-card-documentation-2/ <br>
We won't be accepting pull requests or responding to issues for this project anymore.**

 * License: LGPL 2.1 & BSD
 * &copy; Estonian Information System Authority
 * [Architecture of ID-software](http://open-eid.github.io)

## References:
* [MiniDriver v.7.07 specification](http://www.microsoft.com/whdc/device/input/smartcard/sc-minidriver.mspx)
* [Cryptographic Provider Development Kit](https://www.microsoft.com/en-us/download/details.aspx?id=30688) - cardmod.h
* [Windows Driver Kit Windows 10](https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit) - buildcab.ps1 (stampinf.exe, Inf2Cat.exe)
* [Windows Hardware Certification Kit](https://developer.microsoft.com/en-us/windows/hardware/windows-hardware-lab-kit) - cmck.exe
* [atrfiltr](atrfiltr/readme.txt)

## Building
[![Build Status](https://ci.appveyor.com/api/projects/status/github/open-eid/minidriver?branch=master&svg=true)](https://ci.appveyor.com/project/open-eid/minidriver)

* Execute [buildcab.ps1](buildcab.ps1)

## Running CMCK tests
* [Smart Card Minidriver Certification Test](https://msdn.microsoft.com/en-us/library/windows/hardware/dn390909%28v=vs.85%29.aspx)
* Install esteid driver [install.bat](install.bat)
* Attach 2 test cards, with same PIN
* Set PIN values to [cmck_config.xml](cmck_config.xml) <PinEntry><Value> XML tag
* Execute [runtest.ps1](runtest.ps1)

## Support
Official builds are provided through official distribution point [id.ee](https://www.id.ee/en/article/install-id-software/). If you want support, you need to be using official builds. Contact our support via www.id.ee for assistance.

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
