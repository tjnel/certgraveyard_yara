import "pe"

rule MAL_Compromised_Cert_Akira_Microsoft_330006DF515A14FE3748416FE200000006DF51 {
   meta:
      description         = "Detects Akira with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-11"
      version             = "1.0"

      hash                = "2b7d8a519f44d3105e9fde2770c75efb933994c658855dca7d48c8b4897f81e6"
      malware             = "Akira"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Amy Cherne"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:06:df:51:5a:14:fe:37:48:41:6f:e2:00:00:00:06:df:51"
      cert_thumbprint     = "2087BB914327E937EA6E77FE6C832576338C2AF8"
      cert_valid_from     = "2026-02-11"
      cert_valid_to       = "2026-02-14"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:06:df:51:5a:14:fe:37:48:41:6f:e2:00:00:00:06:df:51"
      )
}
