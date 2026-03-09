import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_24C1C7BD23D4D568C91241E510602337 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-14"
      version             = "1.0"

      hash                = "a769eaa070125ad38353b41c7afa3eff42d8df87e88051c9b1bf8b09c6f602cd"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Limi Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "24:c1:c7:bd:23:d4:d5:68:c9:12:41:e5:10:60:23:37"
      cert_thumbprint     = "A929E6183548BAFA72E5674BF24A53644775F664"
      cert_valid_from     = "2026-01-14"
      cert_valid_to       = "2027-01-14"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "24:c1:c7:bd:23:d4:d5:68:c9:12:41:e5:10:60:23:37"
      )
}
