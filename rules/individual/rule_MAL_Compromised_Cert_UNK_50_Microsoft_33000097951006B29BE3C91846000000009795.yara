import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_33000097951006B29BE3C91846000000009795 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-29"
      version             = "1.0"

      hash                = "de8c50e8ccd240ef9d10ec26c26eeb37a4d1cad7c1e0edf3bb6e5689ec2dde78"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "A&A Interactive Media Group"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:97:95:10:06:b2:9b:e3:c9:18:46:00:00:00:00:97:95"
      cert_thumbprint     = "EA917C96BFA6421586FA48BBAD39783FE0719E91"
      cert_valid_from     = "2026-04-29"
      cert_valid_to       = "2026-05-02"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:97:95:10:06:b2:9b:e3:c9:18:46:00:00:00:00:97:95"
      )
}
