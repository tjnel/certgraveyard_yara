import "pe"

rule MAL_Compromised_Cert_RomCom_Certum_56D0EAAC945D2F0615772047C9C131F5 {
   meta:
      description         = "Detects RomCom with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-13"
      version             = "1.0"

      hash                = "b59448cb4cbabc669a308a76c5dae62c13b0b78cfd4787b5f9e6881945194756"
      malware             = "RomCom"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "PHOTON ARCHITECT DESIGN LAB LLC"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "56:d0:ea:ac:94:5d:2f:06:15:77:20:47:c9:c1:31:f5"
      cert_thumbprint     = "56C04F27F681653E986249E23456B6803F180246"
      cert_valid_from     = "2026-02-13"
      cert_valid_to       = "2027-02-13"

      country             = "KG"
      state               = "Bishkek"
      locality            = "Bishkek"
      email               = "???"
      rdn_serial_number   = "125615-3301-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "56:d0:ea:ac:94:5d:2f:06:15:77:20:47:c9:c1:31:f5"
      )
}
