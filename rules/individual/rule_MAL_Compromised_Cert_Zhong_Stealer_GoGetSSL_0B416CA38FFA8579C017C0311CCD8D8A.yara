import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_GoGetSSL_0B416CA38FFA8579C017C0311CCD8D8A {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (GoGetSSL)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-16"
      version             = "1.0"

      hash                = "99b7658dc52cedff3403e0df0b392828baa3344571593115b2349579c2b840ca"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Heyi Siwei Software Development Studio"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "0b:41:6c:a3:8f:fa:85:79:c0:17:c0:31:1c:cd:8d:8a"
      cert_thumbprint     = "A16812811F22E0DF257295E6BE6E96AFE3A44BE9"
      cert_valid_from     = "2026-04-16"
      cert_valid_to       = "2027-04-15"

      country             = "CN"
      state               = "Shanghai"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "92310101MAK49UUU4R"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "0b:41:6c:a3:8f:fa:85:79:c0:17:c0:31:1c:cd:8d:8a"
      )
}
