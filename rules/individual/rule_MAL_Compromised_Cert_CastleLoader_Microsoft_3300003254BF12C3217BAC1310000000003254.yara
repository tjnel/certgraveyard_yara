import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_3300003254BF12C3217BAC1310000000003254 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-11"
      version             = "1.0"

      hash                = "94f2f31632d8f38a816f3999305d41b6356258c0df1634a1eb2f992c3963fb76"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LEXYL EPSILON"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:32:54:bf:12:c3:21:7b:ac:13:10:00:00:00:00:32:54"
      cert_thumbprint     = "ED784352B39F0543BEBB7E5196C353342760272F"
      cert_valid_from     = "2026-04-11"
      cert_valid_to       = "2026-04-14"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:32:54:bf:12:c3:21:7b:ac:13:10:00:00:00:00:32:54"
      )
}
