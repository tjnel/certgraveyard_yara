import "pe"

rule MAL_Compromised_Cert_Certificate_warming_Sectigo_3E13892931705ACBD704987B3BD70202 {
   meta:
      description         = "Detects Certificate warming with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-28"
      version             = "1.0"

      hash                = "59fd9cd0db55ede4357bc4b3e1cf98303b8cc69fd4876b44eae163b0edefa06c"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Kanon Agro B.V."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "3e:13:89:29:31:70:5a:cb:d7:04:98:7b:3b:d7:02:02"
      cert_thumbprint     = "1d53b9d9da29024e0a8f16802b2c0ec35cd5752a"
      cert_valid_from     = "2026-07-28"
      cert_valid_to       = "2027-07-28"

      country             = "NL"
      state               = "Drenthe"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "3e:13:89:29:31:70:5a:cb:d7:04:98:7b:3b:d7:02:02"
      )
}
