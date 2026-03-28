import "pe"

rule MAL_Compromised_Cert_FakePDF_Leaflet_Sectigo_00B56043A71D40DB6A93D4FF407EE7FB1A {
   meta:
      description         = "Detects FakePDF, Leaflet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-05"
      version             = "1.0"

      hash                = "cbf744e397e2bc34ea2a8fe5cc533bdd575346231300feb7b7e3d8f985626112"
      malware             = "FakePDF, Leaflet"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Haobo Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:b5:60:43:a7:1d:40:db:6a:93:d4:ff:40:7e:e7:fb:1a"
      cert_thumbprint     = "C67C4ABB6B328AB290783081E66FA6C9D96B076F"
      cert_valid_from     = "2026-03-05"
      cert_valid_to       = "2027-03-05"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350205MA2Y7JPQ3Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:b5:60:43:a7:1d:40:db:6a:93:d4:ff:40:7e:e7:fb:1a"
      )
}
