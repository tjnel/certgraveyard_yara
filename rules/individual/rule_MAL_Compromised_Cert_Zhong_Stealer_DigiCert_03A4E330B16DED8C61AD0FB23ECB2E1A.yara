import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_03A4E330B16DED8C61AD0FB23ECB2E1A {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-02"
      version             = "1.0"

      hash                = "d7121915d643fb80745bbfa0ab9425edcc9bc451e7117ec9a7be3b101af50d0a"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Beijing 263 Enterprise Correspondence Co., Ltd."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "03:a4:e3:30:b1:6d:ed:8c:61:ad:0f:b2:3e:cb:2e:1a"
      cert_thumbprint     = "736523909A3402F7A93DFC8841B2BCAD562196D0"
      cert_valid_from     = "2026-04-02"
      cert_valid_to       = "2027-04-30"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "03:a4:e3:30:b1:6d:ed:8c:61:ad:0f:b2:3e:cb:2e:1a"
      )
}
