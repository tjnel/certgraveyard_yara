import "pe"

rule MAL_Compromised_Cert_CastleLoader_DigiCert_0D5713F88E9AFE9B0D1CECA05E0C3532 {
   meta:
      description         = "Detects CastleLoader with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-05"
      version             = "1.0"

      hash                = "5f55c1e837b6fbe5d81d93983166f34f3471a7f20af28ff527b9f140a601ce2d"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: totpwill[.]com"

      signer              = "Dahan David Marketing Ltd."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:57:13:f8:8e:9a:fe:9b:0d:1c:ec:a0:5e:0c:35:32"
      cert_thumbprint     = "01791D58D658C498EFCEE3FE8E87A25DA8F3715E"
      cert_valid_from     = "2026-03-05"
      cert_valid_to       = "2027-03-04"

      country             = "IL"
      state               = "???"
      locality            = "Rekhasim"
      email               = "???"
      rdn_serial_number   = "516001609"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:57:13:f8:8e:9a:fe:9b:0d:1c:ec:a0:5e:0c:35:32"
      )
}
