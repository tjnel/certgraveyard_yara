import "pe"

rule MAL_Compromised_Cert_SmokedHam_Microsoft_3300000F85CC4C7C90F2B50435000000000F85 {
   meta:
      description         = "Detects SmokedHam with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "d642548065350880601937adebaf682058bb733756bcb12a925fce6bb5227dcd"
      malware             = "SmokedHam"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CHRISTOPHER CONLEY"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:0f:85:cc:4c:7c:90:f2:b5:04:35:00:00:00:00:0f:85"
      cert_thumbprint     = "36E647C113914351850141E1CB188CC64294F991"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2026-04-11"

      country             = "US"
      state               = "Alaska"
      locality            = "ANCHORAGE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:0f:85:cc:4c:7c:90:f2:b5:04:35:00:00:00:00:0f:85"
      )
}
