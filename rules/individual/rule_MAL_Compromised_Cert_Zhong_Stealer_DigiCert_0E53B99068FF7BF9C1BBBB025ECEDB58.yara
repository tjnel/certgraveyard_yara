import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_0E53B99068FF7BF9C1BBBB025ECEDB58 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-17"
      version             = "1.0"

      hash                = "4ba01f317dd469c6ce5fb5333828ea5faf6761c263431ebcd0a5c17c06b00868"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "SoftStory G.Zielinski, K.Jez s.c."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0e:53:b9:90:68:ff:7b:f9:c1:bb:bb:02:5e:ce:db:58"
      cert_thumbprint     = "5675D2723A91F4BC5180A0C112187297F3D58F29"
      cert_valid_from     = "2026-04-17"
      cert_valid_to       = "2027-04-16"

      country             = "PL"
      state               = "???"
      locality            = "Tarnów"
      email               = "???"
      rdn_serial_number   = "852721168"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0e:53:b9:90:68:ff:7b:f9:c1:bb:bb:02:5e:ce:db:58"
      )
}
