import "pe"

rule MAL_Compromised_Cert_UpdateLogger_Sectigo_A7DF46AF2D897FF91B38C5DE7EFBC331 {
   meta:
      description         = "Detects UpdateLogger with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-11"
      version             = "1.0"

      hash                = "eeaaa6954b5ab26b2dad9a4cd85857e3eb5b68c9f8026561cc817b0dba664c80"
      malware             = "UpdateLogger"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "YOUR CHANCE j.d.o.o"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "a7:df:46:af:2d:89:7f:f9:1b:38:c5:de:7e:fb:c3:31"
      cert_thumbprint     = "4cee19bfbfbd3ff809829fa7315d4c0246a26a19"
      cert_valid_from     = "2026-09-11"
      cert_valid_to       = "2027-09-11"

      country             = "HR"
      state               = "Grad Zagreb"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "a7:df:46:af:2d:89:7f:f9:1b:38:c5:de:7e:fb:c3:31"
      )
}
