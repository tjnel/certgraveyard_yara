import "pe"

rule MAL_Compromised_Cert_LoremIpsumLoader_Microsoft_330008E2B86CCF64EF87699B7300000008E2B8 {
   meta:
      description         = "Detects LoremIpsumLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "a6fe48609e883ccedff1a74986a61fdf9f3bbf60340384ebba8e28a03bbbabc5"
      malware             = "LoremIpsumLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "Drops Microsoft Teams as a decoy."

      signer              = "PAUL DEPASTENE"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:e2:b8:6c:cf:64:ef:87:69:9b:73:00:00:00:08:e2:b8"
      cert_thumbprint     = "7A728BA5B6157377FB208CAEC354B9B390B7C79B"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2026-04-04"

      country             = "US"
      state               = "Alaska"
      locality            = "ANCHORAGE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:e2:b8:6c:cf:64:ef:87:69:9b:73:00:00:00:08:e2:b8"
      )
}
