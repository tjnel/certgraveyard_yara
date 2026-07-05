import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_24FF6639953E1D1161AF670E86177EF0 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "1f8fbdce2b257b817f8a1c6a8e8703fc3ebbab49df8bc4b41cd12cd76eaf2288"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Jisou Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "24:ff:66:39:95:3e:1d:11:61:af:67:0e:86:17:7e:f0"
      cert_thumbprint     = "4F45BBAF6E9446E44D925C504E8336A9D298E82A"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2027-04-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "24:ff:66:39:95:3e:1d:11:61:af:67:0e:86:17:7e:f0"
      )
}
