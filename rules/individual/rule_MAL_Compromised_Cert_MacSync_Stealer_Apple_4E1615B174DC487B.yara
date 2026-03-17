import "pe"

rule MAL_Compromised_Cert_MacSync_Stealer_Apple_4E1615B174DC487B {
   meta:
      description         = "Detects MacSync Stealer with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-27"
      version             = "1.0"

      hash                = "335509df3ae8aefe79267e70c70edc4cacd6f277ead4b12abd8e5c836f1b39a1"
      malware             = "MacSync Stealer"
      malware_type        = "Unknown"
      malware_notes       = "Fake meeting software ZKcall - info: https://x.com/osint_barbie/status/2032641814822269418"

      signer              = "FERDI AYSEL"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "4e:16:15:b1:74:dc:48:7b"
      cert_thumbprint     = "09F9CB15D45CC6EBD04D8726D8DFFD66BF9D20DC"
      cert_valid_from     = "2026-02-27"
      cert_valid_to       = "2027-02-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "4e:16:15:b1:74:dc:48:7b"
      )
}
