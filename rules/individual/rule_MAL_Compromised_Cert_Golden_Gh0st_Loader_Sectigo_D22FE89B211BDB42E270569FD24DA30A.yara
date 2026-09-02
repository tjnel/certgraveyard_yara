import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Sectigo_D22FE89B211BDB42E270569FD24DA30A {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-15"
      version             = "1.0"

      hash                = "4ca3a0088c63497d7fce4a305c3fd98646badb2278cbca85571b0831f915adde"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tongliao Chuangfa Education Consulting Service Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "d2:2f:e8:9b:21:1b:db:42:e2:70:56:9f:d2:4d:a3:0a"
      cert_thumbprint     = "f87df6d29dbe9c87ab66568a2db834752c28e86a"
      cert_valid_from     = "2026-07-15"
      cert_valid_to       = "2027-07-15"

      country             = "CN"
      state               = "Nei Mongol Zizhiqu"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "d2:2f:e8:9b:21:1b:db:42:e2:70:56:9f:d2:4d:a3:0a"
      )
}
