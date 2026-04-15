import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_33000023311910DDBBFB8386B2000000002331 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-09"
      version             = "1.0"

      hash                = "f7720759f5979b2181d85432730edafac64ab5b9e74a2fedd6bf7bbe22afa06b"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Frank Farris"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:23:31:19:10:dd:bb:fb:83:86:b2:00:00:00:00:23:31"
      cert_thumbprint     = "F6CBA45B562BA250E47CF7FCA4A04E807CD3D80B"
      cert_valid_from     = "2026-04-09"
      cert_valid_to       = "2026-04-12"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:23:31:19:10:dd:bb:fb:83:86:b2:00:00:00:00:23:31"
      )
}
