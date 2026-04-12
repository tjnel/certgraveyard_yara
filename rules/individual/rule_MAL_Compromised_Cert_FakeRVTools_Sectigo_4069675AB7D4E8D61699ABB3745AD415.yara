import "pe"

rule MAL_Compromised_Cert_FakeRVTools_Sectigo_4069675AB7D4E8D61699ABB3745AD415 {
   meta:
      description         = "Detects FakeRVTools with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-09"
      version             = "1.0"

      hash                = "62df37acd922519eaea83a8679c6ff0c051a14768a18e7047f8cf0df4f021ddc"
      malware             = "FakeRVTools"
      malware_type        = "Unknown"
      malware_notes       = "rv-tools[.]org"

      signer              = "Zhongqing Information Technology (Xiamen) Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "40:69:67:5a:b7:d4:e8:d6:16:99:ab:b3:74:5a:d4:15"
      cert_thumbprint     = "85D691439B83BCB9B021E9557ACF3C9BE38143D8"
      cert_valid_from     = "2026-03-09"
      cert_valid_to       = "2027-03-09"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91310115MA1K3BXW5T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "40:69:67:5a:b7:d4:e8:d6:16:99:ab:b3:74:5a:d4:15"
      )
}
