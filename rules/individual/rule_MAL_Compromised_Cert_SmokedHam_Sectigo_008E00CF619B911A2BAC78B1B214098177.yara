import "pe"

rule MAL_Compromised_Cert_SmokedHam_Sectigo_008E00CF619B911A2BAC78B1B214098177 {
   meta:
      description         = "Detects SmokedHam with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-23"
      version             = "1.0"

      hash                = "d57ae70866ba32a5d356eeb09c5ed606e0ab118316d5c9970ee04b460853b303"
      malware             = "SmokedHam"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Jieyang Yusheng Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:8e:00:cf:61:9b:91:1a:2b:ac:78:b1:b2:14:09:81:77"
      cert_thumbprint     = "31FF86255713D2EBC1933D7B5EC8EA3AC25325F2"
      cert_valid_from     = "2025-12-23"
      cert_valid_to       = "2026-12-23"

      country             = "CN"
      state               = "Guangdong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91445221MABN8AL450"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:8e:00:cf:61:9b:91:1a:2b:ac:78:b1:b2:14:09:81:77"
      )
}
