import "pe"

rule MAL_Compromised_Cert_Oyster_SSL_com_064745A9D210EA060B7C5A64E7F75162 {
   meta:
      description         = "Detects Oyster with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-28"
      version             = "1.0"

      hash                = "ce8fb6edbf238116d2c6b102773cdf2329887ba0eeb537ec288bd4e196d08ccc"
      malware             = "Oyster"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PANGEA CIVIL ENGINEERS SRL"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "06:47:45:a9:d2:10:ea:06:0b:7c:5a:64:e7:f7:51:62"
      cert_thumbprint     = "D2F530D7A6A152E3198F6B1326F8FC54098C09D2"
      cert_valid_from     = "2025-08-28"
      cert_valid_to       = "2026-08-28"

      country             = "RO"
      state               = "Ilfov County"
      locality            = "Popeşti-Leordeni"
      email               = "???"
      rdn_serial_number   = "J23 30 2013"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "06:47:45:a9:d2:10:ea:06:0b:7c:5a:64:e7:f7:51:62"
      )
}
