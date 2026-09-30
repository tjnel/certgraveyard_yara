import "pe"

rule MAL_Compromised_Cert_RdWieverLoader_Certum_33FFF9010D45494AF610A8B78626493B {
   meta:
      description         = "Detects RdWieverLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-18"
      version             = "1.0"

      hash                = "9045187c20f7e54e8045f5285b76b0d2615412dc7b963374e2edbbb1418af2f2"
      malware             = "RdWieverLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Liu Juan"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "33:ff:f9:01:0d:45:49:4a:f6:10:a8:b7:86:26:49:3b"
      cert_thumbprint     = "9701e27995f04314a9ab16bd85b951e5b877a783"
      cert_valid_from     = "2026-09-18"
      cert_valid_to       = "2027-09-18"

      country             = "CN"
      state               = "辽宁省"
      locality            = "庄河市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "33:ff:f9:01:0d:45:49:4a:f6:10:a8:b7:86:26:49:3b"
      )
}
