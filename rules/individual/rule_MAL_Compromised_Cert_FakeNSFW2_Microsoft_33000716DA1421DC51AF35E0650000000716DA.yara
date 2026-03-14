import "pe"

rule MAL_Compromised_Cert_FakeNSFW2_Microsoft_33000716DA1421DC51AF35E0650000000716DA {
   meta:
      description         = "Detects FakeNSFW2 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-24"
      version             = "1.0"

      hash                = "6064742f07e20c04ba5944cb8c3998779f8fe8d138f918040401386d78c49771"
      malware             = "FakeNSFW2"
      malware_type        = "Unknown"
      malware_notes       = "C2: cybernetvillage[.]com"

      signer              = "Anquesia Gray"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:16:da:14:21:dc:51:af:35:e0:65:00:00:00:07:16:da"
      cert_thumbprint     = "5FAA30620F8F1C59145824CE27FFAAF09C7A7AEB"
      cert_valid_from     = "2026-02-24"
      cert_valid_to       = "2026-02-27"

      country             = "US"
      state               = "Georgia"
      locality            = "Atlanta"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:16:da:14:21:dc:51:af:35:e0:65:00:00:00:07:16:da"
      )
}
