import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330007EE40B5E0953926959AE700000007EE40 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-07"
      version             = "1.0"

      hash                = "5133561861f6d492b1ac2263849ece599a8dd472828c85bf125027abab22c20d"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = "Fake cryptocurrency wallets builds leading to malicious RMM connections"

      signer              = "Perry Sabrina Ann"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:ee:40:b5:e0:95:39:26:95:9a:e7:00:00:00:07:ee:40"
      cert_thumbprint     = "1A308607C1B0DF68D6638CBC4962549DA4869CCD"
      cert_valid_from     = "2026-04-07"
      cert_valid_to       = "2026-04-10"

      country             = "US"
      state               = "Hawaii"
      locality            = "Wailuku"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:ee:40:b5:e0:95:39:26:95:9a:e7:00:00:00:07:ee:40"
      )
}
