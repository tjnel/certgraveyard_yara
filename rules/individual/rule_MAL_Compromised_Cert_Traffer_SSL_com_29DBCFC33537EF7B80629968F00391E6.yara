import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_29DBCFC33537EF7B80629968F00391E6 {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-30"
      version             = "1.0"

      hash                = "ffa21b0211f4516cc1499f88daa742a7c7b74ba1a1257dd8452d45052ebd83b6"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Fast Home Group LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "29:db:cf:c3:35:37:ef:7b:80:62:99:68:f0:03:91:e6"
      cert_thumbprint     = "3B0BA172B5E9FC44D00BFDE8F90C605E87562832"
      cert_valid_from     = "2026-04-30"
      cert_valid_to       = "2027-04-14"

      country             = "KG"
      state               = "Osh Region"
      locality            = "Osh"
      email               = "???"
      rdn_serial_number   = "163230-3310-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "29:db:cf:c3:35:37:ef:7b:80:62:99:68:f0:03:91:e6"
      )
}
