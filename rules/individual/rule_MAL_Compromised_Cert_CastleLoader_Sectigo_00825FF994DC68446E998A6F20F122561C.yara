import "pe"

rule MAL_Compromised_Cert_CastleLoader_Sectigo_00825FF994DC68446E998A6F20F122561C {
   meta:
      description         = "Detects CastleLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-09"
      version             = "1.0"

      hash                = "068e34ef7cb67e5a8d34b4d6977cd69be00d52b12d119413fb00d9b68dbc63b6"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: newmemorystarter[.]com"

      signer              = "Xiamen Kangchu Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:82:5f:f9:94:dc:68:44:6e:99:8a:6f:20:f1:22:56:1c"
      cert_thumbprint     = "0B5489CB786EC936F4B7504EDD0FF5CBA028C0FA"
      cert_valid_from     = "2026-03-09"
      cert_valid_to       = "2027-03-09"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350206MA33L0MQ2U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:82:5f:f9:94:dc:68:44:6e:99:8a:6f:20:f1:22:56:1c"
      )
}
