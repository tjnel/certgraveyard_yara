import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_72FFA5EF5A1DB3273777C11F4E6EE11D {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-04"
      version             = "1.0"

      hash                = "4080b7ee2043d2574ee516944eea5ea0630942767cd88f516b2b8a6f0e90e68a"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Dino Bartolome"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "72:ff:a5:ef:5a:1d:b3:27:37:77:c1:1f:4e:6e:e1:1d"
      cert_thumbprint     = "BB3D2980F31CBA8F561E95E48E0E4BF5E5298312"
      cert_valid_from     = "2026-04-04"
      cert_valid_to       = "2027-04-02"

      country             = "US"
      state               = "California"
      locality            = "Santa Clara"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "72:ff:a5:ef:5a:1d:b3:27:37:77:c1:1f:4e:6e:e1:1d"
      )
}
