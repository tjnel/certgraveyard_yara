import "pe"

rule MAL_Compromised_Cert_Spyder_SSL_com_2F95071FCAC926220A4A1B6E534CF92A {
   meta:
      description         = "Detects Spyder with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-03"
      version             = "1.0"

      hash                = "34e260c301ee81b228d35ac721b06a3aa41fb5b07835078b5b4e2941fef8aa85"
      malware             = "Spyder"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "ADATPARTNER Software und Systeme GmbH"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2f:95:07:1f:ca:c9:26:22:0a:4a:1b:6e:53:4c:f9:2a"
      cert_thumbprint     = "198271a66381eb3bcc81c56d0e55248ee2984289"
      cert_valid_from     = "2024-12-03"
      cert_valid_to       = "2025-12-03"

      country             = "AT"
      state               = "Vienna"
      locality            = "Vienna"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2f:95:07:1f:ca:c9:26:22:0a:4a:1b:6e:53:4c:f9:2a"
      )
}
