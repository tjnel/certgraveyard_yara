import "pe"

rule MAL_Compromised_Cert_MacSync_Stealer_Apple_7A_69_69_70_46_17_0B_24 {
   meta:
      description         = "Detects MacSync Stealer with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-08"
      version             = "1.0"

      hash                = "7ec35de2f6ca3a0fd9f6b51b79040c778e0e3a8c81ba2f8d7d259d1078c78e8e"
      malware             = "MacSync Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OSMAN ASTUR"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "7a:69:69:70:46:17:0b:24"
      cert_thumbprint     = "550C224F838221923AC4192A2955D644158F3235"
      cert_valid_from     = "2026-09-08"
      cert_valid_to       = "2027-02-01"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "7a:69:69:70:46:17:0b:24"
      )
}
