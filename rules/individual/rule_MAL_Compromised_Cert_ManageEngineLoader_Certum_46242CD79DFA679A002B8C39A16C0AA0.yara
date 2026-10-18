import "pe"

rule MAL_Compromised_Cert_ManageEngineLoader_Certum_46242CD79DFA679A002B8C39A16C0AA0 {
   meta:
      description         = "Detects ManageEngineLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "1d3a8ba207ff46723b5171561ba0e1f99b2f2a0a655a5699c1cf49435f67d7b5"
      malware             = "ManageEngineLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wenbiao Long"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "46:24:2c:d7:9d:fa:67:9a:00:2b:8c:39:a1:6c:0a:a0"
      cert_thumbprint     = "7ebe1191f9cbcd5e7eff4760f8a2761c8cfe9dd5"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2027-04-01"

      country             = "CN"
      state               = "Guangxi"
      locality            = "Luzhai"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "46:24:2c:d7:9d:fa:67:9a:00:2b:8c:39:a1:6c:0a:a0"
      )
}
