import "pe"

rule MAL_Compromised_Cert_Nyx_RMM_SSL_com_75402FF115E7C654F4ACA2F322920F10 {
   meta:
      description         = "Detects Nyx RMM with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-23"
      version             = "1.0"

      hash                = "51ae32063e291a8401388d8d26c42083f855731cc9de8da024c9067e7b1ec6bf"
      malware             = "Nyx RMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Zero NYX Technologies LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "75:40:2f:f1:15:e7:c6:54:f4:ac:a2:f3:22:92:0f:10"
      cert_thumbprint     = "9AD2993D7CE987E89AC001C48099BA9829DCC47A"
      cert_valid_from     = "2026-10-23"
      cert_valid_to       = "2027-10-23"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "75:40:2f:f1:15:e7:c6:54:f4:ac:a2:f3:22:92:0f:10"
      )
}
