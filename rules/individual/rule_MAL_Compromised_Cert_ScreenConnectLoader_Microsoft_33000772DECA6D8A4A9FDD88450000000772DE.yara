import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000772DECA6D8A4A9FDD88450000000772DE {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-17"
      version             = "1.0"

      hash                = "501273de3effcb79912cf8b4da45469ff36584432684ceeaed9be05d6e858300"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GUERRERO DEBRA"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:72:de:ca:6d:8a:4a:9f:dd:88:45:00:00:00:07:72:de"
      cert_thumbprint     = "B2569C6A7DFCD7D3644531165FFFE2023C557959"
      cert_valid_from     = "2026-03-17"
      cert_valid_to       = "2026-03-20"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:72:de:ca:6d:8a:4a:9f:dd:88:45:00:00:00:07:72:de"
      )
}
