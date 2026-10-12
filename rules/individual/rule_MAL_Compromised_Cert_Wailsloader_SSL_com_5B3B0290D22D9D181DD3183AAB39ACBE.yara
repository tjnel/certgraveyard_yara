import "pe"

rule MAL_Compromised_Cert_Wailsloader_SSL_com_5B3B0290D22D9D181DD3183AAB39ACBE {
   meta:
      description         = "Detects Wailsloader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-26"
      version             = "1.0"

      hash                = "1b2432c99b877ac71a37d505ca7165f8d46cb4fc9a98762d54c529c7aef26d71"
      malware             = "Wailsloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Pelican Finland Holding Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "5b:3b:02:90:d2:2d:9d:18:1d:d3:18:3a:ab:39:ac:be"
      cert_thumbprint     = "112AE8C4E41BE6284CE27644781289FE4094880B"
      cert_valid_from     = "2026-08-26"
      cert_valid_to       = "2027-08-26"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "5b:3b:02:90:d2:2d:9d:18:1d:d3:18:3a:ab:39:ac:be"
      )
}
