This sample illustrates how to filter smartcard reader IOCLS that get the ATR from a smartcard
reader driver.  It can be used to make sure that the warm reset ATR matches the cold reset ATR, 
so it will be in compliance with PC/SC.

This is targetted for the Windows 7 WDK.  To build in the Vista WDK, set the following 
environment variable in the build environment command window:

	set VISTA_WDK=1

This filter is based on KMDF.  If you build from the Windows 7 WDK, you must include the KMDF 
co-installer in your driver setup package.


***************************************************************************************

To create an installation application that will add this service as an upper filter for
all smartcard readers {50DD5230-BA8A-11D1-BF5D-0000F805F530}, see this MSDN article:

   http://msdn.microsoft.com/en-us/library/ms791322.aspx


 To manually add driver service:

   sc create atrfiltr binPath= system32\drivers\atrfiltr.sys type= kernel start= demand error= normal

   Add atrfiltr to this registry value:
       HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{50DD5230-BA8A-11D1-BF5D-0000F805F530}\UpperFilters"