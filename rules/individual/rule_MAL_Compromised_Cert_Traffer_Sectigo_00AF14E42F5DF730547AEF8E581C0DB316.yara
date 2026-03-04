import "pe"

rule MAL_Compromised_Cert_Traffer_Sectigo_00AF14E42F5DF730547AEF8E581C0DB316 {
   meta:
      description         = "Detects Traffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-13"
      version             = "1.0"

      hash                = "8904b6b4463f6c08351e06fedf65191110919d71e911e92346c92c957fbf2b84"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SESE IC VE DIS TICARET ANONIM SIRKETI"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:af:14:e4:2f:5d:f7:30:54:7a:ef:8e:58:1c:0d:b3:16"
      cert_thumbprint     = "EA236A07189C37573F41EC47EFCA083208FB3FD9"
      cert_valid_from     = "2026-02-13"
      cert_valid_to       = "2027-02-13"

      country             = "TR"
      state               = "İstanbul"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "1089231"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:af:14:e4:2f:5d:f7:30:54:7a:ef:8e:58:1c:0d:b3:16"
      )
}
