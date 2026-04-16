import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_330008BB04FE247CAAC9FADC7300000008BB04 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-07"
      version             = "1.0"

      hash                = "f30a0cb14d8bf231f56f9e0ad63de7e9fff2a02003ce36649e8a7c8924ea080d"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DAWN RENEE"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:bb:04:fe:24:7c:aa:c9:fa:dc:73:00:00:00:08:bb:04"
      cert_thumbprint     = "2248B47363A65EAE65A7056269BAC274D5A8B13B"
      cert_valid_from     = "2026-04-07"
      cert_valid_to       = "2026-04-10"

      country             = "US"
      state               = "Hawaii"
      locality            = "KULA"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:bb:04:fe:24:7c:aa:c9:fa:dc:73:00:00:00:08:bb:04"
      )
}
