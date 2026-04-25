import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_06500EE65FFBFB6EA4F4B16AB6F910C6 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-04"
      version             = "1.0"

      hash                = "5e841260983954da60716b99306a410898bca4d30c14626553205753f60a6d2f"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "INNOVATIVE CONNECTING PTE. LIMITED"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "06:50:0e:e6:5f:fb:fb:6e:a4:f4:b1:6a:b6:f9:10:c6"
      cert_thumbprint     = "743D976C8A09F830CCBAD9AA1FEBCA18F315F49A"
      cert_valid_from     = "2026-04-04"
      cert_valid_to       = "2027-04-02"

      country             = "SG"
      state               = "???"
      locality            = "Singapore"
      email               = "???"
      rdn_serial_number   = "201812738K"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "06:50:0e:e6:5f:fb:fb:6e:a4:f4:b1:6a:b6:f9:10:c6"
      )
}
