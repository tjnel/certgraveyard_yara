import "pe"

rule MAL_Compromised_Cert_WailsLoader_Certum_637FEC2307D9036A81BF27D1385B58FA {
   meta:
      description         = "Detects WailsLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-18"
      version             = "1.0"

      hash                = "1b708e04860550fddae423916346a799f89a035a9e59b3a9d0a68b51005cf487"
      malware             = "WailsLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LAST HOLDING AS"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "63:7f:ec:23:07:d9:03:6a:81:bf:27:d1:38:5b:58:fa"
      cert_thumbprint     = "5BB03998B82EBA61F0AC45951A3BA5E9DBD8494A"
      cert_valid_from     = "2026-11-18"
      cert_valid_to       = "2027-11-18"

      country             = "NO"
      state               = "???"
      locality            = "Trondheim"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "63:7f:ec:23:07:d9:03:6a:81:bf:27:d1:38:5b:58:fa"
      )
}
