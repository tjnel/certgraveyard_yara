import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_3300003ED76A78FF208BF50426000000003ED7 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-12"
      version             = "1.0"

      hash                = "88a45b1f6489eed1f9470e8671da6389724154d887f58b59ed467dad0149d091"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = "Fake DocuSign setup. From the makers of TrustConnect"

      signer              = "Frank Farris"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:3e:d7:6a:78:ff:20:8b:f5:04:26:00:00:00:00:3e:d7"
      cert_thumbprint     = "7B710AF8EC33E6D4D3555F816C955FBFF864E80C"
      cert_valid_from     = "2026-04-12"
      cert_valid_to       = "2026-04-15"

      country             = "US"
      state               = "Tennessee"
      locality            = "nashville"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:3e:d7:6a:78:ff:20:8b:f5:04:26:00:00:00:00:3e:d7"
      )
}
