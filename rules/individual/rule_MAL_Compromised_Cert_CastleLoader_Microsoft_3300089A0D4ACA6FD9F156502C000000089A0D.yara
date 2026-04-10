import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_3300089A0D4ACA6FD9F156502C000000089A0D {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-30"
      version             = "1.0"

      hash                = "24bcbe18745c1ba65c68f9c55e1208fb0b5ef9f4702ef4165fcb98818d4adcc7"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "godblessaids[.]com"

      signer              = "MIGUEL GUTIERREZLUPERCIO"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:9a:0d:4a:ca:6f:d9:f1:56:50:2c:00:00:00:08:9a:0d"
      cert_thumbprint     = "733820D2144A9FE7DC2584B994C8E373AA00CCA4"
      cert_valid_from     = "2026-03-30"
      cert_valid_to       = "2026-04-02"

      country             = "US"
      state               = "California"
      locality            = "ADELANTO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:9a:0d:4a:ca:6f:d9:f1:56:50:2c:00:00:00:08:9a:0d"
      )
}
