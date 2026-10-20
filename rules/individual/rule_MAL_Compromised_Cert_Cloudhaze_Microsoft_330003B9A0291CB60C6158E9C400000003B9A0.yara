import "pe"

rule MAL_Compromised_Cert_Cloudhaze_Microsoft_330003B9A0291CB60C6158E9C400000003B9A0 {
   meta:
      description         = "Detects Cloudhaze with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-01"
      version             = "1.0"

      hash                = "683e4f9a4e20475bd2e6f79b35e7e5a1764b47b1e754704cacdc97106f1f8074"
      malware             = "Cloudhaze"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TANAGA VENTURES LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:03:b9:a0:29:1c:b6:0c:61:58:e9:c4:00:00:00:03:b9:a0"
      cert_thumbprint     = "10f205a88023681d277f17f2c23ea712f931762c"
      cert_valid_from     = "2026-08-01"
      cert_valid_to       = "2026-08-04"

      country             = "US"
      state               = "New York"
      locality            = "Canandaigua"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:03:b9:a0:29:1c:b6:0c:61:58:e9:c4:00:00:00:03:b9:a0"
      )
}
