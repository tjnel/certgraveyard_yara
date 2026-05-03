import "pe"

rule MAL_Compromised_Cert_Traffer_Sectigo_00CC4C1F1DB6D23A9248EB60A5E7F237DD {
   meta:
      description         = "Detects Traffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-27"
      version             = "1.0"

      hash                = "7b643b230e42e3a2b9a7c03a23331ce39c377b501738d043a868a0620170ce84"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = "Fake meeting app"

      signer              = "Shenzhen Xinfeng E-commerce Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:cc:4c:1f:1d:b6:d2:3a:92:48:eb:60:a5:e7:f2:37:dd"
      cert_thumbprint     = "44073ED8F28F78191FF1A5A2A6EF7F1A228F7ECD"
      cert_valid_from     = "2026-01-27"
      cert_valid_to       = "2027-01-27"

      country             = "CN"
      state               = "Guangdong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91440300MA5F7E1TXW"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:cc:4c:1f:1d:b6:d2:3a:92:48:eb:60:a5:e7:f2:37:dd"
      )
}
