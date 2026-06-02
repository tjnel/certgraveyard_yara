import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000179102F5D5C8325585C99000000017910 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-27"
      version             = "1.0"

      hash                = "98ecad514221b45797cf98ba928644233cc259790889243b6cdbbfcb4a4eb557"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sabrina Perry"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:01:79:10:2f:5d:5c:83:25:58:5c:99:00:00:00:01:79:10"
      cert_thumbprint     = "EC28061B6151FE3ACA1FBFBCC83BA0D1C2F55323"
      cert_valid_from     = "2026-05-27"
      cert_valid_to       = "2026-05-30"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:01:79:10:2f:5d:5c:83:25:58:5c:99:00:00:00:01:79:10"
      )
}
