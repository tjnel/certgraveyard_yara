import "pe"

rule MAL_Compromised_Cert_Traffer_Sectigo_29612758EEBEF8B08BE2BF7D866555B2 {
   meta:
      description         = "Detects Traffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-12"
      version             = "1.0"

      hash                = "e4703084b360679a24d2c3b6b6e4eb1b22a58d3e03d7dec46952dc19168eb9eb"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Yamanganese Network Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "29:61:27:58:ee:be:f8:b0:8b:e2:bf:7d:86:65:55:b2"
      cert_thumbprint     = "495AD4C0C09F98C3C0F88B5C45F2A26028046122"
      cert_valid_from     = "2026-03-12"
      cert_valid_to       = "2027-03-12"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350211MA33QJNX58"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "29:61:27:58:ee:be:f8:b0:8b:e2:bf:7d:86:65:55:b2"
      )
}
