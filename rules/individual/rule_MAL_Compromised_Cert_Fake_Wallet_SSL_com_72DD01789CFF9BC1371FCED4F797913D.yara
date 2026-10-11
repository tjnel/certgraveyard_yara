import "pe"

rule MAL_Compromised_Cert_Fake_Wallet_SSL_com_72DD01789CFF9BC1371FCED4F797913D {
   meta:
      description         = "Detects Fake Wallet with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-16"
      version             = "1.0"

      hash                = "6ba5e05fe22f32863e2421df26ca03af54205d03b8d401a70e67c860d3722989"
      malware             = "Fake Wallet"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Kirsten Brown"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "72:dd:01:78:9c:ff:9b:c1:37:1f:ce:d4:f7:97:91:3d"
      cert_thumbprint     = "94abaf5dcde700e796bcae149fe11a36b91b4964"
      cert_valid_from     = "2026-09-16"
      cert_valid_to       = "2027-09-16"

      country             = "US"
      state               = "Iowa"
      locality            = "Pleasant Hill"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "72:dd:01:78:9c:ff:9b:c1:37:1f:ce:d4:f7:97:91:3d"
      )
}
