import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_33000110CB37960120F559138F0000000110CB {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-15"
      version             = "1.0"

      hash                = "0d024a36cc1c1970a26a7f1ac0daf07d9478bdd6c5b6484284664ebe33eb4815"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: qxvnrta[.]com"

      signer              = "Mahu Agro"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:01:10:cb:37:96:01:20:f5:59:13:8f:00:00:00:01:10:cb"
      cert_thumbprint     = "04E698F3DE03C8B296DCA6E55C8FD4FB56254197"
      cert_valid_from     = "2026-05-15"
      cert_valid_to       = "2026-05-18"

      country             = "NL"
      state               = "Zeeland"
      locality            = "Hengstdijk"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:01:10:cb:37:96:01:20:f5:59:13:8f:00:00:00:01:10:cb"
      )
}
