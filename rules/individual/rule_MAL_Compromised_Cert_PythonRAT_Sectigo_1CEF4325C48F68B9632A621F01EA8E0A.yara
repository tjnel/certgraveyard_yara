import "pe"

rule MAL_Compromised_Cert_PythonRAT_Sectigo_1CEF4325C48F68B9632A621F01EA8E0A {
   meta:
      description         = "Detects PythonRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-19"
      version             = "1.0"

      hash                = "524266500e8341c5c20a548d1f96c55b3696422e761a9c22044f60254d777a8b"
      malware             = "PythonRAT"
      malware_type        = "Unknown"
      malware_notes       = "Fake Advanced IP Scanner from malvertising, executes malicious Python code from third hosts"

      signer              = "Lway Firmware"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "1c:ef:43:25:c4:8f:68:b9:63:2a:62:1f:01:ea:8e:0a"
      cert_thumbprint     = "300cf9210060a44a3e2d76fcf1040452ea4cb1b0"
      cert_valid_from     = "2026-03-19"
      cert_valid_to       = "2027-06-17"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "1c:ef:43:25:c4:8f:68:b9:63:2a:62:1f:01:ea:8e:0a"
      )
}
