import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_61B11EF9726AB2E78132E01BD791B336 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-31"
      version             = "1.0"

      hash                = "d62baef7ed4c7b348f6a7a3c372b97f21ef89150539cc654d92daa9596dd41c1"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "These are historical entries. Additional review is required to understand more."

      signer              = "OOO Skalari"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "61:b1:1e:f9:72:6a:b2:e7:81:32:e0:1b:d7:91:b3:36"
      cert_thumbprint     = "9F7FCFD7E70DD7CD723AC20E5E7CB7AAD1BA976B"
      cert_valid_from     = "2020-12-31"
      cert_valid_to       = "2021-12-31"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "61:b1:1e:f9:72:6a:b2:e7:81:32:e0:1b:d7:91:b3:36"
      )
}
