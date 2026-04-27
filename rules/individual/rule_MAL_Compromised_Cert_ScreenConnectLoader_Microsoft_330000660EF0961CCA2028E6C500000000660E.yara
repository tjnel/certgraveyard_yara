import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000660EF0961CCA2028E6C500000000660E {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-21"
      version             = "1.0"

      hash                = "1375c7d3b694cf197c1669174392f6d1cd579a7adf0385f644667acea52f35f2"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Frank Farris"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:66:0e:f0:96:1c:ca:20:28:e6:c5:00:00:00:00:66:0e"
      cert_thumbprint     = "A2E5CC9AC0D54BB06252DAAC0282DAD0F1EF2F45"
      cert_valid_from     = "2026-04-21"
      cert_valid_to       = "2026-04-24"

      country             = "US"
      state               = "Tennessee"
      locality            = "nashville"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:66:0e:f0:96:1c:ca:20:28:e6:c5:00:00:00:00:66:0e"
      )
}
