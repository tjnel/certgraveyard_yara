import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_3300001A0A0DA6F871B03A582B000000001A0A {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-15"
      version             = "1.0"

      hash                = "62a6e64a7233f4a756d01c54840ff703a620a416929d57eebc0bdac3b9ed2019"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "INFOTECK SOLUTIONS PRIVATE LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:1a:0a:0d:a6:f8:71:b0:3a:58:2b:00:00:00:00:1a:0a"
      cert_thumbprint     = "960C32D541489F1EA2CD0F00427C66B46C49DC9C"
      cert_valid_from     = "2026-04-15"
      cert_valid_to       = "2026-04-18"

      country             = "GB"
      state               = "Greater London"
      locality            = "LONDON"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:1a:0a:0d:a6:f8:71:b0:3a:58:2b:00:00:00:00:1a:0a"
      )
}
