import "pe"

rule MAL_Compromised_Cert_FakeUpdate_Microsoft_330007EB2EFDF089C1D4B0FADC00000007EB2E {
   meta:
      description         = "Detects FakeUpdate with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-06"
      version             = "1.0"

      hash                = "e68dcf3bb3741524ae1c5849bb201ce1abf4a1e92ce74aae8c18a04e7678e31c"
      malware             = "FakeUpdate"
      malware_type        = "Unknown"
      malware_notes       = "C2: apx-broadord[.]com"

      signer              = "Vic Thadhani"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:eb:2e:fd:f0:89:c1:d4:b0:fa:dc:00:00:00:07:eb:2e"
      cert_thumbprint     = "3518742D86893CEA9B44E35DBBC50B536BA20496"
      cert_valid_from     = "2026-04-06"
      cert_valid_to       = "2026-04-09"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:eb:2e:fd:f0:89:c1:d4:b0:fa:dc:00:00:00:07:eb:2e"
      )
}
