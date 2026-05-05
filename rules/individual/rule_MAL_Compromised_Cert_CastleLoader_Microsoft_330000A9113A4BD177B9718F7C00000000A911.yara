import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330000A9113A4BD177B9718F7C00000000A911 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-01"
      version             = "1.0"

      hash                = "785ba9c42deca8cfc69f1aafb371802782d01bc8156a67c5c0d412c5fb3b4e33"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "Delivered through malvertizing. C2: astroflightvision[.]com/f5b27e40-c60d-55fb-9ec1-6627165dd130/pkg1"

      signer              = "Soft Insanity Oy"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:a9:11:3a:4b:d1:77:b9:71:8f:7c:00:00:00:00:a9:11"
      cert_thumbprint     = "2314095E569523EC9D30273370363F4A51B7F566"
      cert_valid_from     = "2026-05-01"
      cert_valid_to       = "2026-05-04"

      country             = "FI"
      state               = "Central Finland"
      locality            = "Hämeenlinna"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:a9:11:3a:4b:d1:77:b9:71:8f:7c:00:00:00:00:a9:11"
      )
}
