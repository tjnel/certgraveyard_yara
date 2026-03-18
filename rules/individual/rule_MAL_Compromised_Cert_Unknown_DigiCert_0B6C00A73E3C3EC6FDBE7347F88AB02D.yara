import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_0B6C00A73E3C3EC6FDBE7347F88AB02D {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-05"
      version             = "1.0"

      hash                = "143fa9567ebbccacceb58201dd85b7206fdf22882ff2cea0da994a513572f14e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mann Technologies LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA256 2021 CA1"
      cert_serial         = "0b:6c:00:a7:3e:3c:3e:c6:fd:be:73:47:f8:8a:b0:2d"
      cert_thumbprint     = "3931A1AE0FF5D92E24758B46B12889D1C9484DAB"
      cert_valid_from     = "2026-03-05"
      cert_valid_to       = "2027-03-02"

      country             = "US"
      state               = "Michigan"
      locality            = "Ann Arbor"
      email               = "???"
      rdn_serial_number   = "802428818"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA256 2021 CA1" and
         sig.serial == "0b:6c:00:a7:3e:3c:3e:c6:fd:be:73:47:f8:8a:b0:2d"
      )
}
