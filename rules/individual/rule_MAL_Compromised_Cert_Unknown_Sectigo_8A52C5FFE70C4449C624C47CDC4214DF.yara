import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_8A52C5FFE70C4449C624C47CDC4214DF {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "e7bc65daf98767646cb1a0e8c3d19cf0db0dce4618a9bcd2d287426cfd2c9034"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Pausatech LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "8a:52:c5:ff:e7:0c:44:49:c6:24:c4:7c:dc:42:14:df"
      cert_thumbprint     = "1b19b26e40686ac2edfc910a5a78d7cb3e9fb7ce"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2027-04-08"

      country             = "US"
      state               = "New Mexico"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "8a:52:c5:ff:e7:0c:44:49:c6:24:c4:7c:dc:42:14:df"
      )
}
