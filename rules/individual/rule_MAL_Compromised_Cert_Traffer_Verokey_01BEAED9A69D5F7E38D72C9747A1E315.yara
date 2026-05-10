import "pe"

rule MAL_Compromised_Cert_Traffer_Verokey_01BEAED9A69D5F7E38D72C9747A1E315 {
   meta:
      description         = "Detects Traffer with compromised cert (Verokey)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-17"
      version             = "1.0"

      hash                = "9062c792d28b5dcabbb5c523bbf2a98a2c7994f5c9daad87940b7068ebb65ce8"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OC Agro ApS"
      cert_issuer_short   = "Verokey"
      cert_issuer         = "Verokey High Assurance Secure Code EV"
      cert_serial         = "01:be:ae:d9:a6:9d:5f:7e:38:d7:2c:97:47:a1:e3:15"
      cert_thumbprint     = "682F6D38026107F36729D6D2AF183C19E0B5DAAC"
      cert_valid_from     = "2026-04-17"
      cert_valid_to       = "2027-04-16"

      country             = "DK"
      state               = "???"
      locality            = "Hammel"
      email               = "???"
      rdn_serial_number   = "36932813"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Verokey High Assurance Secure Code EV" and
         sig.serial == "01:be:ae:d9:a6:9d:5f:7e:38:d7:2c:97:47:a1:e3:15"
      )
}
