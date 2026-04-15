import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_09186DCA3667374ADBD63A2F4FD96365 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-13"
      version             = "1.0"

      hash                = "8509af4802dd79fc503c425c9dda035d9b636f22ffac81a8f04e6a9d080fdcc3"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BlockCerts Blockchain Canada, Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "09:18:6d:ca:36:67:37:4a:db:d6:3a:2f:4f:d9:63:65"
      cert_thumbprint     = "40E56C6EE3E38EB86C7449C7DD58654B5D7FA24F"
      cert_valid_from     = "2026-04-13"
      cert_valid_to       = "2027-04-12"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Victoria"
      email               = "???"
      rdn_serial_number   = "BC1197266"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "09:18:6d:ca:36:67:37:4a:db:d6:3a:2f:4f:d9:63:65"
      )
}
