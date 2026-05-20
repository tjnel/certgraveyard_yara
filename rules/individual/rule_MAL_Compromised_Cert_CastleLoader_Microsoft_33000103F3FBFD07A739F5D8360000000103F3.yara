import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_33000103F3FBFD07A739F5D8360000000103F3 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-12"
      version             = "1.0"

      hash                = "7edec0f7720e8f387ef093741094b5ce139f2e451a6b6f3730f5e6728b1db226"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "TECHNOLOGY APPRAISALS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:01:03:f3:fb:fd:07:a7:39:f5:d8:36:00:00:00:01:03:f3"
      cert_thumbprint     = "22FFB8EA0C0B510D4A49D93D29689C8358EDFF6A"
      cert_valid_from     = "2026-05-12"
      cert_valid_to       = "2026-05-15"

      country             = "GB"
      state               = "Midlothian"
      locality            = "TWICKENHAM"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:01:03:f3:fb:fd:07:a7:39:f5:d8:36:00:00:00:01:03:f3"
      )
}
