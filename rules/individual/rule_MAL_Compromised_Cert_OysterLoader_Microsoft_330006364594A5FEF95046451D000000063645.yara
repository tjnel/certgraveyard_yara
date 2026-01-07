import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_330006364594A5FEF95046451D000000063645 {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-05"
      version             = "1.0"

      hash                = "ae6ab13427b52dbf019348f10740d83903d236f7e703918ffb43667b12c754d2"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "Creates scheduled task named DetectorSpywareSecurity which runs the persistence mechanism."

      signer              = "SOFT CURLS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:06:36:45:94:a5:fe:f9:50:46:45:1d:00:00:00:06:36:45"
      cert_thumbprint     = "DBCF383B156FADEE062B5230656E6E92A8272AF6"
      cert_valid_from     = "2026-01-05"
      cert_valid_to       = "2026-01-08"

      country             = "GB"
      state               = "Essex"
      locality            = "Tilbury"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:06:36:45:94:a5:fe:f9:50:46:45:1d:00:00:00:06:36:45"
      )
}
