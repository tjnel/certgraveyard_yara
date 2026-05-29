import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_3300013112252751AFCC0D2482000000013112 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-19"
      version             = "1.0"

      hash                = "61a37d7d9c9162b44b3c499ad427610278fa492c02d63b278461cd2f41a73f39"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Zeebodem Agro"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:01:31:12:25:27:51:af:cc:0d:24:82:00:00:00:01:31:12"
      cert_thumbprint     = "458CF1F5C34F7A7FD57A15A10BCFE93EF77E4AA2"
      cert_valid_from     = "2026-05-19"
      cert_valid_to       = "2026-05-22"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:01:31:12:25:27:51:af:cc:0d:24:82:00:00:00:01:31:12"
      )
}
