import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_3300009960EB1964A5ABD95DC7000000009960 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-29"
      version             = "1.0"

      hash                = "5ba62826b52725382238994f88ac41b12de9777810d787016cb70887133aecfa"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Soft Insanity Oy"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:99:60:eb:19:64:a5:ab:d9:5d:c7:00:00:00:00:99:60"
      cert_thumbprint     = "CDBAAA0B6E342DE7839035777B79CD585E17BB65"
      cert_valid_from     = "2026-04-29"
      cert_valid_to       = "2026-05-02"

      country             = "FI"
      state               = "Central Finland"
      locality            = "Hämeenlinna"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:99:60:eb:19:64:a5:ab:d9:5d:c7:00:00:00:00:99:60"
      )
}
