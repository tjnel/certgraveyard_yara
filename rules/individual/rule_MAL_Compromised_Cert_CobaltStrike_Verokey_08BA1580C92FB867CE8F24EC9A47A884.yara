import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Verokey_08BA1580C92FB867CE8F24EC9A47A884 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Verokey)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-18"
      version             = "1.0"

      hash                = "956c90138d34d0fb5d32037354ba0256c8a15a15fedcf99898af340979306df1"
      malware             = "CobaltStrike"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "山西荣升源科贸有限公司"
      cert_issuer_short   = "Verokey"
      cert_issuer         = "Verokey High Assurance Secure Code EV"
      cert_serial         = "08:ba:15:80:c9:2f:b8:67:ce:8f:24:ec:9a:47:a8:84"
      cert_thumbprint     = "799317C21A820F3354BB1502E36765A490DE0979"
      cert_valid_from     = "2025-05-18"
      cert_valid_to       = "2026-06-18"

      country             = "CN"
      state               = "山西省"
      locality            = "太原市"
      email               = "???"
      rdn_serial_number   = "91140105MA0LK0WH8B"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Verokey High Assurance Secure Code EV" and
         sig.serial == "08:ba:15:80:c9:2f:b8:67:ce:8f:24:ec:9a:47:a8:84"
      )
}
