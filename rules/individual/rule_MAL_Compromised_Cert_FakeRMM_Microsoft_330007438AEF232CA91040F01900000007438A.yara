import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_330007438AEF232CA91040F01900000007438A {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-05"
      version             = "1.0"

      hash                = "14c62111879e9c9d738ed901db6533da38846454ed3b001ddbb3ad64840683f0"
      malware             = "FakeRMM"
      malware_type        = "Remote access tool"
      malware_notes       = "From the makers of TrustConnect."

      signer              = "DAWN MALLORY"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:43:8a:ef:23:2c:a9:10:40:f0:19:00:00:00:07:43:8a"
      cert_thumbprint     = "A743D20741824C2C3C6B361A40DA338592AEDD59"
      cert_valid_from     = "2026-03-05"
      cert_valid_to       = "2026-03-08"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:43:8a:ef:23:2c:a9:10:40:f0:19:00:00:00:07:43:8a"
      )
}
