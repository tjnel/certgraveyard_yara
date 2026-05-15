import "pe"

rule MAL_Compromised_Cert_UNK_53_Certum_4916AD68D1B4EC438EB47B6BEE0F6183 {
   meta:
      description         = "Detects UNK-53 with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-24"
      version             = "1.0"

      hash                = "22a3ed2d3721450f884f4c219e3afd7a36c571d65392534f38787fca605e328c"
      malware             = "UNK-53"
      malware_type        = "Remote access tool"
      malware_notes       = "Telegram based rat, with C2 idantre[.]com"

      signer              = "Huizhou Ningda Times Supply Chain Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "49:16:ad:68:d1:b4:ec:43:8e:b4:7b:6b:ee:0f:61:83"
      cert_thumbprint     = "391044793C1A58620417CAC1B7E38BD84C6AD69A"
      cert_valid_from     = "2026-04-24"
      cert_valid_to       = "2027-04-24"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Huizhou"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "49:16:ad:68:d1:b4:ec:43:8e:b4:7b:6b:ee:0f:61:83"
      )
}
