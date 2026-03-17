import "pe"

rule MAL_Compromised_Cert_BlackSanta_Sectigo_9E0433AB8DD97C709FF850DDAB967C87 {
   meta:
      description         = "Detects BlackSanta with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-04-08"
      version             = "1.0"

      hash                = "83fcc6bf733751bab43e92d31b810c4cecd4d8640668d2ed26f47f62edd942cf"
      malware             = "BlackSanta"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ADLICE (Julien ASCOET)"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "9e:04:33:ab:8d:d9:7c:70:9f:f8:50:dd:ab:96:7c:87"
      cert_thumbprint     = "ae0d8e0dd13b1d61f4b1eb4ac6aa49ef5c27a965d25cd22588486894ba18d7fd"
      cert_valid_from     = "2022-04-08"
      cert_valid_to       = "2023-04-08"

      country             = "FR"
      state               = "Loire-Atlantique"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "793 308 925 00023"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "9e:04:33:ab:8d:d9:7c:70:9f:f8:50:dd:ab:96:7c:87"
      )
}
