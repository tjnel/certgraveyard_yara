import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330008E899C483597477738F5700000008E899 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-02"
      version             = "1.0"

      hash                = "a23404d697356773f2a970c190d2025c2aba7737dc12ccaab012fbd6cf19921f"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Elisa Olea"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:e8:99:c4:83:59:74:77:73:8f:57:00:00:00:08:e8:99"
      cert_thumbprint     = "F3A3B7B587D2538898B2ABD66739167387F4B283"
      cert_valid_from     = "2026-04-02"
      cert_valid_to       = "2026-04-05"

      country             = "US"
      state               = "Arizona"
      locality            = "gilbert"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:e8:99:c4:83:59:74:77:73:8f:57:00:00:00:08:e8:99"
      )
}
