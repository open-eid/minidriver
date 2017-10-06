Minidriver version [3.12.1](https://github.com/open-eid/minidriver/releases/tag/v3.12.1) release notes
-----------------------------------
- Fix ECDSA CMCK tests
- Add ECDH support
- minor build and code fixes

[Full Changelog](https://github.com/open-eid/minidriver/compare/v3.12.0...v3.12.1)

Minidriver version [3.12.0](https://github.com/open-eid/minidriver/releases/tag/v3.12.0) release notes
-----------------------------------
- Remove SmartCardPP
- ECDSA token support
- major cleanup and rewrite

[Full Changelog](https://github.com/open-eid/minidriver/compare/v3.11.1...v3.12.0)

Minidriver version 3.11 release notes
-----------------------------------
Changes compared to ver 3.10

- Fix PIN blocked error message in case of PINPAD smartcard reader. IB-3836
- Fix wrong PIN presented error message in case of PINPAD smartcard reader. IB-2152
- Fix PIN timeout error message in case of PINPAD smartcard reader. IB-3361
- Fix PIN cancel PINPAD behaviour


Minidriver version 3.10 release notes
-----------------------------------
Changes compared to ver 3.8

- Fixed RDP problem with WUDF driver.
- Added functionality of reading card owner's personal code, first name and surname from AUTH certificate in case of Digi-ID cards. 
- Added SMARTCARDPP_NOPINPAD environment variable support for all platforms.
- Fixed PINPAD detection bug that occurred when two or more readers were connected.

Known issues:
- Minidriver does not support SHA-384 and SHA-512 hash algorithms in case of Digi-ID cards.


Minidriver version 3.8 release notes
-----------------------------------

- Added support for new ID card version v3.5.1 to Minidriver.
- Ended support for CSP, only Minidriver is supported and tested in all Windows platforms
