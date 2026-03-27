import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_00CB77AE87CFDDF44C5CCE239AA4AEF766 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-13"
      version             = "1.0"

      hash                = "92ac278d0c29af3c5d177c19a7ac00df2980686ae8ff5e2af0871bc187a2f699"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SAINTNEPTUNE SOCIEDAD LIMITADA"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:cb:77:ae:87:cf:dd:f4:4c:5c:ce:23:9a:a4:ae:f7:66"
      cert_thumbprint     = "25A5D70E5371602FD6793AB2F7E76DD9A639950D"
      cert_valid_from     = "2026-02-13"
      cert_valid_to       = "2027-02-13"

      country             = "ES"
      state               = "Sevilla"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:cb:77:ae:87:cf:dd:f4:4c:5c:ce:23:9a:a4:ae:f7:66"
      )
}
