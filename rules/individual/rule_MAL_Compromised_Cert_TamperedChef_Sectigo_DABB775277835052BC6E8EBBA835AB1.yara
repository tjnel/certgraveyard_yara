import "pe"

rule MAL_Compromised_Cert_TamperedChef_Sectigo_DABB775277835052BC6E8EBBA835AB1 {
   meta:
      description         = "Detects TamperedChef with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "2f4502f29a7c61ebb300849d07b182a8f07efe8f72c2b84b10c74989e851158f"
      malware             = "TamperedChef"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Serve-o-lution LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "da:bb:77:52:77:83:50:52:bc:6e:8e:bb:a8:35:ab:1"
      cert_thumbprint     = "913746695bf2ab84c4c648475b25655f933365bc"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2027-03-23"

      country             = "UA"
      state               = "Kyiv"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "da:bb:77:52:77:83:50:52:bc:6e:8e:bb:a8:35:ab:1"
      )
}
