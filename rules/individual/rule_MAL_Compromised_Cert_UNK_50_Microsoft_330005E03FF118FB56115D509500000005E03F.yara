import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330005E03FF118FB56115D509500000005E03F {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-19"
      version             = "1.0"

      hash                = "fb15d6ff1b499858aab40d8bad0e5e9032e22b11d686d22e144dbcf1a81f3976"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BELFAST CITY FITNESS LTD"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:e0:3f:f1:18:fb:56:11:5d:50:95:00:00:00:05:e0:3f"
      cert_thumbprint     = "6C31F4669A20EF6792BC7893B934E865476EF340"
      cert_valid_from     = "2025-12-19"
      cert_valid_to       = "2025-12-22"

      country             = "GB"
      state               = "Birmingham"
      locality            = "Birmingham"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:e0:3f:f1:18:fb:56:11:5d:50:95:00:00:00:05:e0:3f"
      )
}
