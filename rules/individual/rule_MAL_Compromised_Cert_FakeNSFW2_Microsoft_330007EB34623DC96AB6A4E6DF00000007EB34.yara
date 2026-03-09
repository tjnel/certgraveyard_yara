import "pe"

rule MAL_Compromised_Cert_FakeNSFW2_Microsoft_330007EB34623DC96AB6A4E6DF00000007EB34 {
   meta:
      description         = "Detects FakeNSFW2 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-02"
      version             = "1.0"

      hash                = "1755169c2eb55a83e75e30f4420f76456c28cd3af64ff2532b030cf5195843ce"
      malware             = "FakeNSFW2"
      malware_type        = "Unknown"
      malware_notes       = "C2: cybernetvillage[.]com"

      signer              = "Ricardo Reis"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:07:eb:34:62:3d:c9:6a:b6:a4:e6:df:00:00:00:07:eb:34"
      cert_thumbprint     = "57843D8FF7FCC27CBFE8FBFA2121EB68C1FFBED8"
      cert_valid_from     = "2026-03-02"
      cert_valid_to       = "2026-03-05"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:07:eb:34:62:3d:c9:6a:b6:a4:e6:df:00:00:00:07:eb:34"
      )
}
