import "pe"

rule MAL_Compromised_Cert_Certificate_warming_Microsoft_330003CAE1D77B4A543425190200000003CAE1 {
   meta:
      description         = "Detects Certificate warming with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-26"
      version             = "1.0"

      hash                = "1423084a8aaa721627f9674fd4ba3679b27acdc7992001b91adb41f0457756b5"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Kanon Agro B.V."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:03:ca:e1:d7:7b:4a:54:34:25:19:02:00:00:00:03:ca:e1"
      cert_thumbprint     = "a6a8108856639088a0ff71fb3e6f75d3da822a42"
      cert_valid_from     = "2026-07-26"
      cert_valid_to       = "2026-07-29"

      country             = "NL"
      state               = "Drenthe"
      locality            = "Midlaren"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:03:ca:e1:d7:7b:4a:54:34:25:19:02:00:00:00:03:ca:e1"
      )
}
