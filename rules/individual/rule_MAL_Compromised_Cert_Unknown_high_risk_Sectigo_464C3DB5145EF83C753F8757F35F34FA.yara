import "pe"

rule MAL_Compromised_Cert_Unknown_high_risk_Sectigo_464C3DB5145EF83C753F8757F35F34FA {
   meta:
      description         = "Detects Unknown, high risk with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-26"
      version             = "1.0"

      hash                = "f4e255dfdf3d23774b0067797cac0f986f1690abbeec217eb60029dcaa7425f8"
      malware             = "Unknown, high risk"
      malware_type        = "Unknown"
      malware_notes       = "Use of this certificate is being sold of Fiverr and is open to abuse."

      signer              = "Amir Dow"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "46:4c:3d:b5:14:5e:f8:3c:75:3f:87:57:f3:5f:34:fa"
      cert_thumbprint     = "BAB1402518EC594D9C052872C6AB4D1B14A7DBC8"
      cert_valid_from     = "2025-11-26"
      cert_valid_to       = "2028-11-25"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "46:4c:3d:b5:14:5e:f8:3c:75:3f:87:57:f3:5f:34:fa"
      )
}
