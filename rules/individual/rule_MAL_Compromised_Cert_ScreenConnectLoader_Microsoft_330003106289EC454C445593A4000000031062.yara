import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330003106289EC454C445593A4000000031062 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-11"
      version             = "1.0"

      hash                = "2170731dc04008613d2396665cbe68ef9f3862fd44cc4277d3877d273001ffa4"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "jasmine mosby"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:03:10:62:89:ec:45:4c:44:55:93:a4:00:00:00:03:10:62"
      cert_thumbprint     = "89086D38FD152C809E040C621400139EF6AECD71"
      cert_valid_from     = "2026-07-11"
      cert_valid_to       = "2026-07-14"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:03:10:62:89:ec:45:4c:44:55:93:a4:00:00:00:03:10:62"
      )
}
