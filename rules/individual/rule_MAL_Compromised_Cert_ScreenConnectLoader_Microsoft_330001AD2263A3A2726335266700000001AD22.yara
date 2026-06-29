import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001AD2263A3A2726335266700000001AD22 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-04"
      version             = "1.0"

      hash                = "fc88c9a59f28c2acfadcbaed5e006b2bb023f0a59f8b4a2e27f26606ac59b8a3"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:ad:22:63:a3:a2:72:63:35:26:67:00:00:00:01:ad:22"
      cert_thumbprint     = "AAF3B902238E04135DB8DB59905DE73990F083AF"
      cert_valid_from     = "2026-06-04"
      cert_valid_to       = "2026-06-07"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:ad:22:63:a3:a2:72:63:35:26:67:00:00:00:01:ad:22"
      )
}
