import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_330007DD8DF1C1AF342CDF84D300000007DD8D {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-19"
      version             = "1.0"

      hash                = "dee64b39920c45f3f833185178a6490e9f35c2229a3ab911b4c1698e03bad8a9"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installers posing as a fake RMM tool. Ref: https://www.proofpoint.com/us/blog/threat-insight/dont-trustconnect-its-a-rat"

      signer              = "Khyree Woodberry"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:dd:8d:f1:c1:af:34:2c:df:84:d3:00:00:00:07:dd:8d"
      cert_thumbprint     = "CD49434C7A5D88FC5022F4268115A77C2C032333"
      cert_valid_from     = "2026-02-19"
      cert_valid_to       = "2026-02-22"

      country             = "US"
      state               = "Maryland"
      locality            = "baltimore"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:dd:8d:f1:c1:af:34:2c:df:84:d3:00:00:00:07:dd:8d"
      )
}
