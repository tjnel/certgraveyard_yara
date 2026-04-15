import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_330008F14B653BF56DB14D28A300000008F14B {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-05"
      version             = "1.0"

      hash                = "f48a433d7eac6c4eb0f008468719bd0b7d653d1eca155b8a78dc17516fce5bf2"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DAWN RENEE"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:f1:4b:65:3b:f5:6d:b1:4d:28:a3:00:00:00:08:f1:4b"
      cert_thumbprint     = "F35658413600D8A73C2A642497FE9BE3B5948A2E"
      cert_valid_from     = "2026-04-05"
      cert_valid_to       = "2026-04-08"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:f1:4b:65:3b:f5:6d:b1:4d:28:a3:00:00:00:08:f1:4b"
      )
}
