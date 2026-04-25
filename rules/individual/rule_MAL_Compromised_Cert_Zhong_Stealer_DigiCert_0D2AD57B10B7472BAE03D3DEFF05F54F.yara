import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_0D2AD57B10B7472BAE03D3DEFF05F54F {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-10"
      version             = "1.0"

      hash                = "93d458ce6ebc98b2884e4a76c026d731a9f793cfcc6d514d4952ad6bf28fe8ac"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "LENOVO (UNITED STATES) INC."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:2a:d5:7b:10:b7:47:2b:ae:03:d3:de:ff:05:f5:4f"
      cert_thumbprint     = "7C0AF30E97249F78CDDF66E47D65EEECB34BA2B8"
      cert_valid_from     = "2026-04-10"
      cert_valid_to       = "2027-04-11"

      country             = "US"
      state               = "North Carolina"
      locality            = "Morrisville"
      email               = "???"
      rdn_serial_number   = "3912990"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:2a:d5:7b:10:b7:47:2b:ae:03:d3:de:ff:05:f5:4f"
      )
}
