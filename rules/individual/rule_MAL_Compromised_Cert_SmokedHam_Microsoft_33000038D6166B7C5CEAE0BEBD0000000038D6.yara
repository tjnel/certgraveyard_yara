import "pe"

rule MAL_Compromised_Cert_SmokedHam_Microsoft_33000038D6166B7C5CEAE0BEBD0000000038D6 {
   meta:
      description         = "Detects SmokedHam with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-12"
      version             = "1.0"

      hash                = "9fd74c0e4f2bb5a078162e33a6c8c665f0afbdedd09a9c9f14437696da495f71"
      malware             = "SmokedHam"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CHRISTOPHER CONLEY"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:38:d6:16:6b:7c:5c:ea:e0:be:bd:00:00:00:00:38:d6"
      cert_thumbprint     = "C47BCB83356B2A5D05ACE7E18F1579669EF125EE"
      cert_valid_from     = "2026-04-12"
      cert_valid_to       = "2026-04-15"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:38:d6:16:6b:7c:5c:ea:e0:be:bd:00:00:00:00:38:d6"
      )
}
