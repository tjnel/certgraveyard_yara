import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330008A7EC06F2B46F1B5209E700000008A7EC {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "6343c19effc0804d6ce4051a87c19825de05bb2203caed4292b5e7a5c5d33af6"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Rosangel Villalobos"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:a7:ec:06:f2:b4:6f:1b:52:09:e7:00:00:00:08:a7:ec"
      cert_thumbprint     = "95a8ac86bc6b72425a766a630edb335e44bc57d2"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2026-03-26"

      country             = "US"
      state               = "Arizona"
      locality            = "Tolleson"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:a7:ec:06:f2:b4:6f:1b:52:09:e7:00:00:00:08:a7:ec"
      )
}
