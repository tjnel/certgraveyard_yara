import "pe"

rule MAL_Compromised_Cert_CastleLoader_DigiCert_09BAD6F035789BF34EFA23620A2A34DF {
   meta:
      description         = "Detects CastleLoader with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-30"
      version             = "1.0"

      hash                = "a5beab87db308852e8e062e93892a88af5ba41bf5a857155b6d80a8f6b9e3762"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: nyvionly[.]com"

      signer              = "SERPENTINE SOLAR LIMITED"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "09:ba:d6:f0:35:78:9b:f3:4e:fa:23:62:0a:2a:34:df"
      cert_thumbprint     = "BD49A8C2E9847EC07081C84ECEEEB02E27B223AE"
      cert_valid_from     = "2026-03-30"
      cert_valid_to       = "2027-04-01"

      country             = "IE"
      state               = "???"
      locality            = "Dublin"
      email               = "???"
      rdn_serial_number   = "556711"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "09:ba:d6:f0:35:78:9b:f3:4e:fa:23:62:0a:2a:34:df"
      )
}
