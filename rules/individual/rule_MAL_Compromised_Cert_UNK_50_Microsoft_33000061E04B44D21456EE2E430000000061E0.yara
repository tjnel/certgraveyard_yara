import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_33000061E04B44D21456EE2E430000000061E0 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-21"
      version             = "1.0"

      hash                = "7ab839e9a3acbf09288c9272e0df6606c747df4ad689985b4afd11998b5facd1"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "A&A Interactive Media Group"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:61:e0:4b:44:d2:14:56:ee:2e:43:00:00:00:00:61:e0"
      cert_thumbprint     = "ADE1F5F138F2A4656DA10457CCE1412AD2048931"
      cert_valid_from     = "2026-04-21"
      cert_valid_to       = "2026-04-24"

      country             = "NL"
      state               = "Noord-Brabant"
      locality            = "Helmond"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:61:e0:4b:44:d2:14:56:ee:2e:43:00:00:00:00:61:e0"
      )
}
