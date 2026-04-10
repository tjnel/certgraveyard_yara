import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_01AF6469365C81AD7222E60FB1317062 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-02"
      version             = "1.0"

      hash                = "00ed464e867fdc31ac4eb4e18757fe4b79b2f79ff63cc469cfcfeb205df20af0"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "深圳市优品投资顾问有限公司"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "01:af:64:69:36:5c:81:ad:72:22:e6:0f:b1:31:70:62"
      cert_thumbprint     = "4CF40F13CC4B8209FE56D8E9B1FD277C6E9D1ED7"
      cert_valid_from     = "2026-04-02"
      cert_valid_to       = "2027-07-04"

      country             = "CN"
      state               = "广东省"
      locality            = "深圳市"
      email               = "???"
      rdn_serial_number   = "9144030013299983XL"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "01:af:64:69:36:5c:81:ad:72:22:e6:0f:b1:31:70:62"
      )
}
