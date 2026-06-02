import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330007918348954D80D6573A7D000000079183 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-22"
      version             = "1.0"

      hash                = "7ee9ca0d9e78bed5fee51205f037c9f5c82440405624928433770c85389e0851"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:91:83:48:95:4d:80:d6:57:3a:7d:00:00:00:07:91:83"
      cert_thumbprint     = "02B9410C6FAD1175A225C3D2A997BCAE29DE3973"
      cert_valid_from     = "2026-03-22"
      cert_valid_to       = "2026-03-25"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:91:83:48:95:4d:80:d6:57:3a:7d:00:00:00:07:91:83"
      )
}
