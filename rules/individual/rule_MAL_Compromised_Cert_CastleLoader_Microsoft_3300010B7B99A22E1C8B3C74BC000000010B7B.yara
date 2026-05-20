import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_3300010B7B99A22E1C8B3C74BC000000010B7B {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-14"
      version             = "1.0"

      hash                = "d26ea6828cc01ae151d99bbee78c4e6d132e9077842a558bce3901fa0970d9be"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TECHNOLOGY APPRAISALS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:01:0b:7b:99:a2:2e:1c:8b:3c:74:bc:00:00:00:01:0b:7b"
      cert_thumbprint     = "64CA73BE82CC5A0BD1B3CE22093A80F2FF8260CA"
      cert_valid_from     = "2026-05-14"
      cert_valid_to       = "2026-05-17"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:01:0b:7b:99:a2:2e:1c:8b:3c:74:bc:00:00:00:01:0b:7b"
      )
}
