import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_3300001D099986F3B1F6209D43000000001D09 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-15"
      version             = "1.0"

      hash                = "d68bfbe6e957ae3189533534c3408f2991bd18bdb5601278f6250509714d51df"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Frank Farris"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:1d:09:99:86:f3:b1:f6:20:9d:43:00:00:00:00:1d:09"
      cert_thumbprint     = "F83F739E4D15E6B3DFD2D16A039563669190F43B"
      cert_valid_from     = "2026-04-15"
      cert_valid_to       = "2026-04-18"

      country             = "US"
      state               = "Tennessee"
      locality            = "nashville"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:1d:09:99:86:f3:b1:f6:20:9d:43:00:00:00:00:1d:09"
      )
}
