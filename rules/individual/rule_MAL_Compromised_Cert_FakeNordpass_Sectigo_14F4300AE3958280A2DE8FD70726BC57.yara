import "pe"

rule MAL_Compromised_Cert_FakeNordpass_Sectigo_14F4300AE3958280A2DE8FD70726BC57 {
   meta:
      description         = "Detects FakeNordpass with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "c21004a37adf77147a2e53cec7fd2b21a1e47da538f8868f0b4865d0d8aff629"
      malware             = "FakeNordpass"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "INFOTECK SOLUTIONS PRIVATE LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "14:f4:30:0a:e3:95:82:80:a2:de:8f:d7:07:26:bc:57"
      cert_thumbprint     = "DC7F37E4DCE75CC7CDD18857AFE9415AB39266AF"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2027-03-17"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "14:f4:30:0a:e3:95:82:80:a2:de:8f:d7:07:26:bc:57"
      )
}
