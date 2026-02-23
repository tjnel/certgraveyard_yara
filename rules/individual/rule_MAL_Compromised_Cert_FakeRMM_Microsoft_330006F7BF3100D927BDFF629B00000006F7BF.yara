import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_330006F7BF3100D927BDFF629B00000006F7BF {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-18"
      version             = "1.0"

      hash                = "8888ab30499348d868135da1d7e80369efab7b53904a802ecc60615827bd9dbd"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installers posing as a fake RMM tool. Ref: https://www.proofpoint.com/us/blog/threat-insight/dont-trustconnect-its-a-rat"

      signer              = "PERRY CHANG"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:06:f7:bf:31:00:d9:27:bd:ff:62:9b:00:00:00:06:f7:bf"
      cert_thumbprint     = "804F5783F9F798494EB5D22A677D91779EFA0464"
      cert_valid_from     = "2026-02-18"
      cert_valid_to       = "2026-02-21"

      country             = "US"
      state               = "California"
      locality            = "Laguna Niguel"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:06:f7:bf:31:00:d9:27:bd:ff:62:9b:00:00:00:06:f7:bf"
      )
}
