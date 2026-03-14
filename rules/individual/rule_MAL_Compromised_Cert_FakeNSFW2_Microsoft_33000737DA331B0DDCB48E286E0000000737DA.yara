import "pe"

rule MAL_Compromised_Cert_FakeNSFW2_Microsoft_33000737DA331B0DDCB48E286E0000000737DA {
   meta:
      description         = "Detects FakeNSFW2 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-03"
      version             = "1.0"

      hash                = "74548adc0158b704c0776920cf0f8cfc2c3022b2cae56b5aae239d70df1f7d7f"
      malware             = "FakeNSFW2"
      malware_type        = "Unknown"
      malware_notes       = "C2: cybernetvillage[.]com"

      signer              = "Ricardo Reis"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:37:da:33:1b:0d:dc:b4:8e:28:6e:00:00:00:07:37:da"
      cert_thumbprint     = "046F95F2AE7D7CF333F0E53EC8357387EA83250F"
      cert_valid_from     = "2026-03-03"
      cert_valid_to       = "2026-03-06"

      country             = "US"
      state               = "South Carolina"
      locality            = "Johnston"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:37:da:33:1b:0d:dc:b4:8e:28:6e:00:00:00:07:37:da"
      )
}
