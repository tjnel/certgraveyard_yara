import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_CC4C1F1DB6D23A9248EB60A5E7F237DD {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-27"
      version             = "1.0"

      hash                = "3c90a389afe27e34d76ead6419314337e27c18c0de17745c2c7dba2b939f92da"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shenzhen Xinfeng E-commerce Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "cc:4c:1f:1d:b6:d2:3a:92:48:eb:60:a5:e7:f2:37:dd"
      cert_thumbprint     = "44073ed8f28f78191ff1a5a2a6ef7f1a228f7ecd"
      cert_valid_from     = "2026-01-27"
      cert_valid_to       = "2027-01-27"

      country             = "CN"
      state               = "Guangdong Sheng"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "cc:4c:1f:1d:b6:d2:3a:92:48:eb:60:a5:e7:f2:37:dd"
      )
}
