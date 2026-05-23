import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00C311BB931EE237BC5EDB1FC6469D8777 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-19"
      version             = "1.0"

      hash                = "b03f5eba41b74cef1ac2926d4ac13c0b7b36e3df414796b11920bb89a077de77"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Lway Firmware"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:c3:11:bb:93:1e:e2:37:bc:5e:db:1f:c6:46:9d:87:77"
      cert_thumbprint     = "134EB01A66CB8D51861907FD416F3A8686E76AB4"
      cert_valid_from     = "2026-03-19"
      cert_valid_to       = "2027-06-17"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "3462375-9"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:c3:11:bb:93:1e:e2:37:bc:5e:db:1f:c6:46:9d:87:77"
      )
}
