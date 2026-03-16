import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_3300076A64AE1DBFA635A9F333000000076A64 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-14"
      version             = "1.0"

      hash                = "60171e71774630b9f5c824e2a4ee4742aff1461e0c1910395430ba1592c469cd"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "C2: foxkids[.]us"

      signer              = "Sergio Villafane"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:6a:64:ae:1d:bf:a6:35:a9:f3:33:00:00:00:07:6a:64"
      cert_thumbprint     = "00E6B8B764E30C4AB259B23BB2F18674B47794BD"
      cert_valid_from     = "2026-03-14"
      cert_valid_to       = "2026-03-17"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:6a:64:ae:1d:bf:a6:35:a9:f3:33:00:00:00:07:6a:64"
      )
}
