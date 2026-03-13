import "pe"

rule MAL_Compromised_Cert_CastleLoader_Sectigo_03C2DE2572AEE65EF1A2009CD0853040 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-30"
      version             = "1.0"

      hash                = "11875de4d8789bc95ba00bc040b8160549252dae2fb18f948d9380fb0d297c32"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: mazafakadadscomeone[.]com"

      signer              = "CULTURE AND EDUCATION INTERNATIONAL LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "03:c2:de:25:72:ae:e6:5e:f1:a2:00:9c:d0:85:30:40"
      cert_thumbprint     = "17FD026BB1E5707ABADE28CEFC2A2CC4B4F350AD"
      cert_valid_from     = "2026-01-30"
      cert_valid_to       = "2027-01-30"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "03:c2:de:25:72:ae:e6:5e:f1:a2:00:9c:d0:85:30:40"
      )
}
