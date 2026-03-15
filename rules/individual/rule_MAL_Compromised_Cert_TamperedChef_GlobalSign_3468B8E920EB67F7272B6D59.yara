import "pe"

rule MAL_Compromised_Cert_TamperedChef_GlobalSign_3468B8E920EB67F7272B6D59 {
   meta:
      description         = "Detects TamperedChef with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-07-15"
      version             = "1.0"

      hash                = "b8dd436636a416eb9b55431ed7b60eb14771ad93e972f1248b8d8149d4ee5272"
      malware             = "TamperedChef"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hexagon AI Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign Extended Validation CodeSigning CA - SHA256 - G3"
      cert_serial         = "34:68:b8:e9:20:eb:67:f7:27:2b:6d:59"
      cert_thumbprint     = "1F230143E3D832A259D29475BEAC4988E5ED3EF3"
      cert_valid_from     = "2020-07-15"
      cert_valid_to       = "2023-07-16"

      country             = "MT"
      state               = "Gozo Region"
      locality            = "Victoria"
      email               = "???"
      rdn_serial_number   = "C95306"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign Extended Validation CodeSigning CA - SHA256 - G3" and
         sig.serial == "34:68:b8:e9:20:eb:67:f7:27:2b:6d:59"
      )
}
