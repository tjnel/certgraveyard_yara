import "pe"

rule MAL_Compromised_Cert_Certificate_warming_Microsoft_330000EB76AF81A96ABE3D945E00000000EB76 {
   meta:
      description         = "Detects Certificate warming with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-09"
      version             = "1.0"

      hash                = "de560f54deb9e7f1ca4930836b78b4d470add3886b8fd41cf8295c43c034075e"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = "This file is benign but is being distributed to increase trust in the certificate."

      signer              = "ELISA M OLEA"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:eb:76:af:81:a9:6a:be:3d:94:5e:00:00:00:00:eb:76"
      cert_thumbprint     = "C9FB34FBDB07E1366CDD86D473D5216AD2838AA4"
      cert_valid_from     = "2026-05-09"
      cert_valid_to       = "2026-05-12"

      country             = "US"
      state               = "Arizona"
      locality            = "GILBERT"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:eb:76:af:81:a9:6a:be:3d:94:5e:00:00:00:00:eb:76"
      )
}
