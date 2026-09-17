import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_D0B158D6CAA58F79E9DAE3B3F97A49FF {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "5a8b794b9aece519ddbfeab8bec50bc40922f107f24ce143e571762a8c5446da"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Shengdakai Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "d0:b1:58:d6:ca:a5:8f:79:e9:da:e3:b3:f9:7a:49:ff"
      cert_thumbprint     = "f63d37d988f79fc8edb2992d0ac5efacafcb0868"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2027-04-01"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "d0:b1:58:d6:ca:a5:8f:79:e9:da:e3:b3:f9:7a:49:ff"
      )
}
