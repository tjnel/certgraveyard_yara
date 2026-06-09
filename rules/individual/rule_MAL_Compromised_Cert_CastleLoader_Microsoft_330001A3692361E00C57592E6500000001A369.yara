import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330001A3692361E00C57592E6500000001A369 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-03"
      version             = "1.0"

      hash                = "f50f825a64cb9c0435bc11db9225445687f8d1a44dba972a50ffa4dff600e72f"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOFTWARE ANALYTICS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:a3:69:23:61:e0:0c:57:59:2e:65:00:00:00:01:a3:69"
      cert_thumbprint     = "8B29656615BF826ACDADC3AF26FD4EFA25B33E9A"
      cert_valid_from     = "2026-06-03"
      cert_valid_to       = "2026-06-06"

      country             = "GB"
      state               = "Greater London"
      locality            = "Harrow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:a3:69:23:61:e0:0c:57:59:2e:65:00:00:00:01:a3:69"
      )
}
