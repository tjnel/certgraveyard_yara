import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_33000882A36F2FF4A04720A3E70000000882A3 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-17"
      version             = "1.0"

      hash                = "f8e78a1a7a6a6b6c40ad5f2d72d2eac1814af01efe96a13e4b9bf7dce2ed438f"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Teresa Boswell"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:82:a3:6f:2f:f4:a0:47:20:a3:e7:00:00:00:08:82:a3"
      cert_thumbprint     = "CEF61640D10C7191BF1D0F267D99436EEBB205AA"
      cert_valid_from     = "2026-03-17"
      cert_valid_to       = "2026-03-20"

      country             = "US"
      state               = "Arizona"
      locality            = "mesa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:82:a3:6f:2f:f4:a0:47:20:a3:e7:00:00:00:08:82:a3"
      )
}
