import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_330007E159397E8634FE81A78200000007E159 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-20"
      version             = "1.0"

      hash                = "7303a95893caaf748406a1931d062f5b64320c96852fedefd0a6f6291f29caa3"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installers posing as a fake RMM tool. Ref: https://www.proofpoint.com/us/blog/threat-insight/dont-trustconnect-its-a-rat"

      signer              = "PERRY CHANG"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:e1:59:39:7e:86:34:fe:81:a7:82:00:00:00:07:e1:59"
      cert_thumbprint     = "81182228E5B76F958E1DD90E1EA4E58DACD8884C"
      cert_valid_from     = "2026-02-20"
      cert_valid_to       = "2026-02-23"

      country             = "US"
      state               = "California"
      locality            = "Laguna Niguel"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:e1:59:39:7e:86:34:fe:81:a7:82:00:00:00:07:e1:59"
      )
}
