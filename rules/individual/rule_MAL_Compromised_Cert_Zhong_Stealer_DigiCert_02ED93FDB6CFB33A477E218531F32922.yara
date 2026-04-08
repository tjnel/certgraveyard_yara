import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_02ED93FDB6CFB33A477E218531F32922 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-02"
      version             = "1.0"

      hash                = "56541af54c5b4ad7de32560f780f0e606e5bf67170ad3bc241c9e2d75ea3f760"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MobSoft Co., Ltd"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "02:ed:93:fd:b6:cf:b3:3a:47:7e:21:85:31:f3:29:22"
      cert_thumbprint     = "ED445CC41A622A74F000D04FA74A60BD846E0B1C"
      cert_valid_from     = "2026-04-02"
      cert_valid_to       = "2027-04-02"

      country             = "KR"
      state               = "Seoul"
      locality            = "Guro District"
      email               = "???"
      rdn_serial_number   = "110111-8502117"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "02:ed:93:fd:b6:cf:b3:3a:47:7e:21:85:31:f3:29:22"
      )
}
