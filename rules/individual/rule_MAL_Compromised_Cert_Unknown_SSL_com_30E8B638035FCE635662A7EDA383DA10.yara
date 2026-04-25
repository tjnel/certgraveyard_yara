import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_30E8B638035FCE635662A7EDA383DA10 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-19"
      version             = "1.0"

      hash                = "fc760d6358637c983b085305d7925fbb9e9d27e593728ead81e89cd26a27156b"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "AI generated analysis: https://github.com/Squiblydoo/Remnux_Reports/blob/main/Reports%20by%20hash/fc760d6358637c983b085305d7925fbb9e9d27e593728ead81e89cd26a27156b_StartGoMyPhoto/analysis_report.md \nSeems to be complex obfuscation."

      signer              = "Andre Fathurrohman"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "30:e8:b6:38:03:5f:ce:63:56:62:a7:ed:a3:83:da:10"
      cert_thumbprint     = "30399F059CBCAE465962CD7389A1E7FA3635CA96"
      cert_valid_from     = "2025-05-19"
      cert_valid_to       = "2026-05-19"

      country             = "ID"
      state               = "Lampung"
      locality            = "Sukamulya Banyumas"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "30:e8:b6:38:03:5f:ce:63:56:62:a7:ed:a3:83:da:10"
      )
}
