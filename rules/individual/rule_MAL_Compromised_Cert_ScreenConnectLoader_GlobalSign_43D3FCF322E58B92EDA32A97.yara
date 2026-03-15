import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_GlobalSign_43D3FCF322E58B92EDA32A97 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-10"
      version             = "1.0"

      hash                = "dcd7401df7ccd4fcc04373dabd8841b01003e9f280880dbb36eb2df62c73c88e"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MROScanner OÜ"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "43:d3:fc:f3:22:e5:8b:92:ed:a3:2a:97"
      cert_thumbprint     = "232F4ED434E89F3B70838F65A7E178C05F96EB58"
      cert_valid_from     = "2026-03-10"
      cert_valid_to       = "2027-03-11"

      country             = "EE"
      state               = "Harju maakond"
      locality            = "Tallinn"
      email               = "info@mroscanner.com"
      rdn_serial_number   = "16179587"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "43:d3:fc:f3:22:e5:8b:92:ed:a3:2a:97"
      )
}
