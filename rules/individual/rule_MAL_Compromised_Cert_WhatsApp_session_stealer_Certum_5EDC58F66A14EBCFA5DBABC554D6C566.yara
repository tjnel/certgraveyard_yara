import "pe"

rule MAL_Compromised_Cert_WhatsApp_session_stealer_Certum_5EDC58F66A14EBCFA5DBABC554D6C566 {
   meta:
      description         = "Detects WhatsApp session stealer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-25"
      version             = "1.0"

      hash                = "d5fad2e86439e2105fdccb37532d277fd45b877d82dd9e7c2737a35049aae508"
      malware             = "WhatsApp session stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hangmai Yuandong Technology Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5e:dc:58:f6:6a:14:eb:cf:a5:db:ab:c5:54:d6:c5:66"
      cert_thumbprint     = "25862FC79BDD1794419687C8A80D6F31A16598E8"
      cert_valid_from     = "2026-03-25"
      cert_valid_to       = "2027-03-25"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510105MAE5UDAH9J"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5e:dc:58:f6:6a:14:eb:cf:a5:db:ab:c5:54:d6:c5:66"
      )
}
