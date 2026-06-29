import "pe"

rule MAL_Compromised_Cert_SoftHub_GlobalSign_1A68E8AEFBDBD2B972F8D6BD {
   meta:
      description         = "Detects SoftHub with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-12"
      version             = "1.0"

      hash                = "973e231cfa1e7d1ad1a409dbe5c501b85f76d1c8ce167dd388fa11d71b1c86a6"
      malware             = "SoftHub"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GANPATI ESTATES LLP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1a:68:e8:ae:fb:db:d2:b9:72:f8:d6:bd"
      cert_thumbprint     = "EC2838563CB09495725AD38CB645212EE24258C8"
      cert_valid_from     = "2025-06-12"
      cert_valid_to       = "2026-06-13"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "kisanvyas126@gmail.com"
      rdn_serial_number   = "AAD-5839"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1a:68:e8:ae:fb:db:d2:b9:72:f8:d6:bd"
      )
}
