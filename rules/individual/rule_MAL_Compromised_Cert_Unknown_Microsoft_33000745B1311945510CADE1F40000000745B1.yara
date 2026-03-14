import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_33000745B1311945510CADE1F40000000745B1 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-05"
      version             = "1.0"

      hash                = "092fb803ea1777965f61e4e60a8ba0a1c5b1eb688ce3554ddbaf0bf28f6bb254"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "C2: cybernetvillage[.]com"

      signer              = "Ricardo Reis"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:45:b1:31:19:45:51:0c:ad:e1:f4:00:00:00:07:45:b1"
      cert_thumbprint     = "D3C597AC9C1FE85C8CF754EACCF70FEE216E85FE"
      cert_valid_from     = "2026-03-05"
      cert_valid_to       = "2026-03-08"

      country             = "US"
      state               = "South Carolina"
      locality            = "Johnston"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:45:b1:31:19:45:51:0c:ad:e1:f4:00:00:00:07:45:b1"
      )
}
