import "pe"

rule MAL_Compromised_Cert_Unknown_GoGetSSL_0B9FFB5061C28B5C82AFAA11DDC55210 {
   meta:
      description         = "Detects Unknown with compromised cert (GoGetSSL)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-16"
      version             = "1.0"

      hash                = "2686a649c29df76f437b54c815f359d0652155a4657aaf8479b6398d8cfc78aa"
      malware             = "Unknown"
      malware_type        = "Loader"
      malware_notes       = "The malware functions as a loader and drops several infostealer payloads. https://app.any.run/tasks/35f70eb9-b5f1-44ea-8a82-d0c40cbe6900/"

      signer              = "SIFE SOFTWARE LLC"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "0b:9f:fb:50:61:c2:8b:5c:82:af:aa:11:dd:c5:52:10"
      cert_thumbprint     = "92E19541858C250F9C197BE06726146A408C89E1"
      cert_valid_from     = "2026-03-16"
      cert_valid_to       = "2027-03-15"

      country             = "US"
      state               = "Wyoming"
      locality            = "Jackson"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "0b:9f:fb:50:61:c2:8b:5c:82:af:aa:11:dd:c5:52:10"
      )
}
