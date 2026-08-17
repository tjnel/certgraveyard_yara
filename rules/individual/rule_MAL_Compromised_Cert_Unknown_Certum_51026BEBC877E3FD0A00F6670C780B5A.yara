import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_51026BEBC877E3FD0A00F6670C780B5A {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-30"
      version             = "1.0"

      hash                = "cba149a008d192efcbbaee98fe28255577f420ea29465f990cd38065b5766765"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RUBIN - CZ s.r.o."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "51:02:6b:eb:c8:77:e3:fd:0a:00:f6:67:0c:78:0b:5a"
      cert_thumbprint     = "9356cced940d3d9e26b99084c7994c23b62b5cb3"
      cert_valid_from     = "2026-07-30"
      cert_valid_to       = "2027-07-30"

      country             = "CZ"
      state               = "Středočeský kraj"
      locality            = "Běleč"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "51:02:6b:eb:c8:77:e3:fd:0a:00:f6:67:0c:78:0b:5a"
      )
}
