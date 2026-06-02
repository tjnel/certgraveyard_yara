import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330008B0AB187518E226CBC1AF00000008B0AB {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-24"
      version             = "1.0"

      hash                = "f25ca888d6345c4fcae707af9255297f10113592ed360f9a790d3b6f2ceefc50"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:b0:ab:18:75:18:e2:26:cb:c1:af:00:00:00:08:b0:ab"
      cert_thumbprint     = "B3236A4C4B20F4028ED7635E7EA489A712870ED3"
      cert_valid_from     = "2026-03-24"
      cert_valid_to       = "2026-03-27"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:b0:ab:18:75:18:e2:26:cb:c1:af:00:00:00:08:b0:ab"
      )
}
