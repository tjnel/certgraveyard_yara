import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_E6852643D4986F08A4EF725A3C5E16A {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-31"
      version             = "1.0"

      hash                = "26646cd038fad9dbc2c2e5988043516b3f2fbc03e1f197a7cef8380e3499ba7d"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Keroro Software LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert G5 CS RSA4096 SHA384 2021 CA1"
      cert_serial         = "e6:85:26:43:d4:98:6f:08:a4:ef:72:5a:3c:5e:16:a"
      cert_thumbprint     = "2669886f9e03a472630625da11b5ce084445bd03"
      cert_valid_from     = "2025-07-31"
      cert_valid_to       = "2028-09-26"

      country             = "CN"
      state               = "广东省"
      locality            = "深圳市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert G5 CS RSA4096 SHA384 2021 CA1" and
         sig.serial == "e6:85:26:43:d4:98:6f:08:a4:ef:72:5a:3c:5e:16:a"
      )
}
