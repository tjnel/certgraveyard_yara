import "pe"

rule MAL_Compromised_Cert_FakeDocument_Sectigo_00ACB4AF64AC061AADB00B5370B4CA0246 {
   meta:
      description         = "Detects FakeDocument with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-24"
      version             = "1.0"

      hash                = "d1158944a1b572f911de5bd2cab6f7b1c5537a69dbb2e148ccf7107521670b5a"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Jiaming Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ac:b4:af:64:ac:06:1a:ad:b0:0b:53:70:b4:ca:02:46"
      cert_thumbprint     = "442BB718BB5A3FDE09008B9C9C7AD2625E38B506"
      cert_valid_from     = "2026-03-24"
      cert_valid_to       = "2027-03-24"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350203MADN0B6E4T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ac:b4:af:64:ac:06:1a:ad:b0:0b:53:70:b4:ca:02:46"
      )
}
