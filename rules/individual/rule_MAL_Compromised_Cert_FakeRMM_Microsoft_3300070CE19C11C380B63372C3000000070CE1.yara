import "pe"

rule MAL_Compromised_Cert_FakeRMM_Microsoft_3300070CE19C11C380B63372C3000000070CE1 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-23"
      version             = "1.0"

      hash                = "b24cd241b4f39d65a521b580dccd67ee702ad905d8f955f1b6f3e4c3ca476202"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installers posing as a RMM tool. Ref: https://www.proofpoint.com/us/blog/threat-insight/dont-trustconnect-its-a-rat"

      signer              = "NICHOLAS HALL"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:0c:e1:9c:11:c3:80:b6:33:72:c3:00:00:00:07:0c:e1"
      cert_thumbprint     = "1C491F0E99E4A88B814F27448CE49EF9EED91BF8"
      cert_valid_from     = "2026-02-23"
      cert_valid_to       = "2026-02-26"

      country             = "US"
      state               = "Indiana"
      locality            = "HANOVER"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:0c:e1:9c:11:c3:80:b6:33:72:c3:00:00:00:07:0c:e1"
      )
}
