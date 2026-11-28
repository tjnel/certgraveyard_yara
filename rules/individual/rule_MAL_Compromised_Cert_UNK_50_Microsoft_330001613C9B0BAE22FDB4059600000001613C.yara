import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330001613C9B0BAE22FDB4059600000001613C {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-27"
      version             = "1.0"

      hash                = "56cc26e88c064b0c423aa8ad6530e58f91d1e4d28fab1a8bcedef16a6582b4d2"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "F.F.A.P. Hurkmans Beheer B.V."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:61:3c:9b:0b:ae:22:fd:b4:05:96:00:00:00:01:61:3c"
      cert_thumbprint     = "7e06bc934d6e118bba1f0076f37667122c6a8e51"
      cert_valid_from     = "2026-05-27"
      cert_valid_to       = "2026-05-30"

      country             = "NL"
      state               = "Gelderland"
      locality            = "Nederhemert"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:61:3c:9b:0b:ae:22:fd:b4:05:96:00:00:00:01:61:3c"
      )
}
