import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_7E0D2428F8B3793BE0947AB4DAB9473C {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-17"
      version             = "1.0"

      hash                = "30bf84c083d8b9068fa2a2ef675c485f5d7071acef3d8a123f03cedf6f64c4d7"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ELITE SOFTWARE LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "7e:0d:24:28:f8:b3:79:3b:e0:94:7a:b4:da:b9:47:3c"
      cert_thumbprint     = "94666E3AE756E64EF3ACD75B223829CF4ADCC7C0"
      cert_valid_from     = "2026-03-17"
      cert_valid_to       = "2027-03-17"

      country             = "US"
      state               = "California"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "B20260092982"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "7e:0d:24:28:f8:b3:79:3b:e0:94:7a:b4:da:b9:47:3c"
      )
}
