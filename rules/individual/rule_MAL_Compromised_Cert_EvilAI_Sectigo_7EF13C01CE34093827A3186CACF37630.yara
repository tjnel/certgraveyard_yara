import "pe"

rule MAL_Compromised_Cert_EvilAI_Sectigo_7EF13C01CE34093827A3186CACF37630 {
   meta:
      description         = "Detects EvilAI with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-11"
      version             = "1.0"

      hash                = "3f906f28de0b804c69c26792820e29a208ce57fe54da0eaef3e7020793bcbce3"
      malware             = "EvilAI"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sphere Ignite Studio LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "7e:f1:3c:01:ce:34:09:38:27:a3:18:6c:ac:f3:76:30"
      cert_thumbprint     = "4F9CD354F88C7262259B7E4A2420196315740F36"
      cert_valid_from     = "2025-11-11"
      cert_valid_to       = "2026-11-11"

      country             = "US"
      state               = "Wyoming"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "2025-001774961"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "7e:f1:3c:01:ce:34:09:38:27:a3:18:6c:ac:f3:76:30"
      )
}
