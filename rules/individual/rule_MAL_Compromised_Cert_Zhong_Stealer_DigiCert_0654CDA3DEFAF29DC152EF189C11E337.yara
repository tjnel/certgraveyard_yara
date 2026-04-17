import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_0654CDA3DEFAF29DC152EF189C11E337 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-10"
      version             = "1.0"

      hash                = "02f95352c8d55f41f53339283ffed6f1cf548b2c5040aa9d1e37bafcd9fa55b4"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shuttle Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "06:54:cd:a3:de:fa:f2:9d:c1:52:ef:18:9c:11:e3:37"
      cert_thumbprint     = "62E64E8159B28E092DA95048ED6A525B738460E6"
      cert_valid_from     = "2026-04-10"
      cert_valid_to       = "2027-04-14"

      country             = "TW"
      state               = "Taipei City"
      locality            = "Neihu District"
      email               = "???"
      rdn_serial_number   = "20980880"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "06:54:cd:a3:de:fa:f2:9d:c1:52:ef:18:9c:11:e3:37"
      )
}
