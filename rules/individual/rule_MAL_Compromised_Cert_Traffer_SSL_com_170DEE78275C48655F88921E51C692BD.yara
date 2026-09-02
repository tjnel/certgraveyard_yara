import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_170DEE78275C48655F88921E51C692BD {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-03"
      version             = "1.0"

      hash                = "cbdeb451713f76acef172a93809ac16cbfdfcaf61d39093d204b84dfa772b4c1"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AirTiki ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "17:0d:ee:78:27:5c:48:65:5f:88:92:1e:51:c6:92:bd"
      cert_thumbprint     = "f1929acdfbfc64787a7e35d659c9b70aa7d99d6c"
      cert_valid_from     = "2026-08-03"
      cert_valid_to       = "2027-08-03"

      country             = "DK"
      state               = "Sjælland"
      locality            = "Nysted"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "17:0d:ee:78:27:5c:48:65:5f:88:92:1e:51:c6:92:bd"
      )
}
