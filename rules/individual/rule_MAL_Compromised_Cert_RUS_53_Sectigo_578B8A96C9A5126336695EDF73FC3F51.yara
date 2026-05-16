import "pe"

rule MAL_Compromised_Cert_RUS_53_Sectigo_578B8A96C9A5126336695EDF73FC3F51 {
   meta:
      description         = "Detects RUS-53 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-27"
      version             = "1.0"

      hash                = "85456be1c9b293aa8ad788d27ffc6f8bb2118b5cbfce1522c9168ac1236a88e2"
      malware             = "RUS-53"
      malware_type        = "Backdoor"
      malware_notes       = "Unknown malware"

      signer              = "Gansu Shishida Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "57:8b:8a:96:c9:a5:12:63:36:69:5e:df:73:fc:3f:51"
      cert_thumbprint     = "8D13A6823E19DC9C131559CCD1F565A295F50425"
      cert_valid_from     = "2026-04-27"
      cert_valid_to       = "2027-04-27"

      country             = "CN"
      state               = "Gansu Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91620102MA74H77T7D"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "57:8b:8a:96:c9:a5:12:63:36:69:5e:df:73:fc:3f:51"
      )
}
