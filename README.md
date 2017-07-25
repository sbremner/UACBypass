# UACBypass
Performs a UAC bypass for 32-bit Win7 systems if the user already has admin rights. This allows an attacker to execute with elevated privileges without required any interaction from the user.

The code takes advantage of a load order hijack with sysprep.exe and cryptbase.dll. Since sysprep.exe is set to auto-elevate, it is possible to abuse sysprep.exe's process with the load order hijack to elevate to admin privileges without triggering UAC.

See this article for more on auto-elevate:
https://technet.microsoft.com/en-us/library/2009.07.uac.aspx#id0560031

All credit for the method goes to K. Kleissner whom also references credit to http://www.pretentiousname.com/misc/win7_uac_whitelist2.html. My code is just a reimplementation of his work.
