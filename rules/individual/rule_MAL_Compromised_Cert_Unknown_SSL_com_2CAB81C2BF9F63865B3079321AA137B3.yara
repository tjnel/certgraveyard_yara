import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_2CAB81C2BF9F63865B3079321AA137B3 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-17"
      version             = "1.0"

      hash                = "121ed0b57841063122ed3100f0becbe97aeeec5780d7895322829cd16b71f272"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SERHAT DOGAN"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "2c:ab:81:c2:bf:9f:63:86:5b:30:79:32:1a:a1:37:b3"
      cert_thumbprint     = "c848543577cd211fcf0ff85883bb49b140b32504"
      cert_valid_from     = "2026-08-17"
      cert_valid_to       = "2027-08-17"

      country             = "GB"
      state               = "---"
      locality            = "Enfield"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "2c:ab:81:c2:bf:9f:63:86:5b:30:79:32:1a:a1:37:b3"
      )
}
