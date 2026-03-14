import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_009C32E4F7CE30CE6283084B355EC9FBAF {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-20"
      version             = "1.0"

      hash                = "848507853b02e04494a7a3086a9cd01da038f4cea8ae1729cc6ed1297cbd1a4a"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Tuochao Software Development Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:9c:32:e4:f7:ce:30:ce:62:83:08:4b:35:5e:c9:fb:af"
      cert_thumbprint     = "CA7CC1E79BDD0BB5C189385EAEC7BA022A9EF215"
      cert_valid_from     = "2026-01-20"
      cert_valid_to       = "2027-01-20"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350203MA31LTE57B"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:9c:32:e4:f7:ce:30:ce:62:83:08:4b:35:5e:c9:fb:af"
      )
}
