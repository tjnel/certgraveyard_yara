import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_330007153BFD5290301D62863F00000007153B {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-13"
      version             = "1.0"

      hash                = "52ad5eab557738df3755f4a609bd2f554a1cf4f6707a55e01f29178f5131161f"
      malware             = "OysterLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "M.F.A.M. COMPANY, L.L.C."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:15:3b:fd:52:90:30:1d:62:86:3f:00:00:00:07:15:3b"
      cert_thumbprint     = "3993E8FD03EDE7DD30940465A5313CEB02B2840B"
      cert_valid_from     = "2026-01-13"
      cert_valid_to       = "2026-01-16"

      country             = "US"
      state               = "Colorado"
      locality            = "Greeley"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:15:3b:fd:52:90:30:1d:62:86:3f:00:00:00:07:15:3b"
      )
}
