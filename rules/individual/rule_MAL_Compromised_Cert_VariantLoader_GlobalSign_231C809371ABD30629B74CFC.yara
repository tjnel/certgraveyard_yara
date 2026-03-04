import "pe"

rule MAL_Compromised_Cert_VariantLoader_GlobalSign_231C809371ABD30629B74CFC {
   meta:
      description         = "Detects VariantLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-05"
      version             = "1.0"

      hash                = "f262806eac85417246608d3053280fa74a04011b0836b25f74691503301d2ff3"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: 188.137.248.50"

      signer              = "Individual entrepreneur Turenko Daniil Aleksandrovich"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "23:1c:80:93:71:ab:d3:06:29:b7:4c:fc"
      cert_thumbprint     = "46C494F1B059AF936FFB04E4B7BA1685F37A2CE4"
      cert_valid_from     = "2026-02-05"
      cert_valid_to       = "2027-02-06"

      country             = "RU"
      state               = "Moscow Oblast"
      locality            = "Noginsk"
      email               = "dany.tur2004@gmail.com"
      rdn_serial_number   = "325508100325374"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "23:1c:80:93:71:ab:d3:06:29:b7:4c:fc"
      )
}
