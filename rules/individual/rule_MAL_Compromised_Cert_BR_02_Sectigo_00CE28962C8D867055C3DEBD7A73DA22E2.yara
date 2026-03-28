import "pe"

rule MAL_Compromised_Cert_BR_02_Sectigo_00CE28962C8D867055C3DEBD7A73DA22E2 {
   meta:
      description         = "Detects BR-02 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-12"
      version             = "1.0"

      hash                = "7982894ad1279e7942fc7f5906f0ced2e04056045a81b02f123c9856d48caeee"
      malware             = "BR-02"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Lingmeng Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ce:28:96:2c:8d:86:70:55:c3:de:bd:7a:73:da:22:e2"
      cert_thumbprint     = "7C652CF2B559B873B8B7D129AD4AB37CC9724F64"
      cert_valid_from     = "2026-03-12"
      cert_valid_to       = "2027-03-12"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350206051171854W"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ce:28:96:2c:8d:86:70:55:c3:de:bd:7a:73:da:22:e2"
      )
}
