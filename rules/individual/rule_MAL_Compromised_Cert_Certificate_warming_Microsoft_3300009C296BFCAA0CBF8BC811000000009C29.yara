import "pe"

rule MAL_Compromised_Cert_Certificate_warming_Microsoft_3300009C296BFCAA0CBF8BC811000000009C29 {
   meta:
      description         = "Detects Certificate warming with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-29"
      version             = "1.0"

      hash                = "9d9f128f61aec17af6a955b4577e1e6af493b3c4b6dfc5be5a4976f6f644ea05"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = "This certificate is being 'warmed', being used to sign benign files before deploying malware."

      signer              = "Mark Boitel"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:9c:29:6b:fc:aa:0c:bf:8b:c8:11:00:00:00:00:9c:29"
      cert_thumbprint     = "19DF54453CFEF1DDD8016C611575FDE47565F32B"
      cert_valid_from     = "2026-04-29"
      cert_valid_to       = "2026-05-02"

      country             = "US"
      state               = "Ohio"
      locality            = "Dublin"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:9c:29:6b:fc:aa:0c:bf:8b:c8:11:00:00:00:00:9c:29"
      )
}
