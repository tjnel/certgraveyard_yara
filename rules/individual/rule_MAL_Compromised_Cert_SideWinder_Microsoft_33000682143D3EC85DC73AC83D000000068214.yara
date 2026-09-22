import "pe"

rule MAL_Compromised_Cert_SideWinder_Microsoft_33000682143D3EC85DC73AC83D000000068214 {
   meta:
      description         = "Detects SideWinder with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-15"
      version             = "1.0"

      hash                = "c096e92e58774622c527dd69f4aafb14f4d0bdfdda7599c6023dc2da43935eba"
      malware             = "SideWinder"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Brittany Ann Martin"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:06:82:14:3d:3e:c8:5d:c7:3a:c8:3d:00:00:00:06:82:14"
      cert_thumbprint     = "ffdfee0fca6a184e7289edccf8a2d25485664e8f"
      cert_valid_from     = "2026-09-15"
      cert_valid_to       = "2026-09-18"

      country             = "US"
      state               = "fl"
      locality            = "riverview"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:06:82:14:3d:3e:c8:5d:c7:3a:c8:3d:00:00:00:06:82:14"
      )
}
