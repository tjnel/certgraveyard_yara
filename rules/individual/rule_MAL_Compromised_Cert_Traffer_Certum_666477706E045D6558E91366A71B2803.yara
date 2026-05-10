import "pe"

rule MAL_Compromised_Cert_Traffer_Certum_666477706E045D6558E91366A71B2803 {
   meta:
      description         = "Detects Traffer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-24"
      version             = "1.0"

      hash                = "d59d3443120c77b1cf524a1926074dccbe9fa0ce2054f4b7962ec1301b8ca4c5"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OC Agro ApS"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "66:64:77:70:6e:04:5d:65:58:e9:13:66:a7:1b:28:03"
      cert_thumbprint     = "0A02E02B09ABF83FEA7C9FEE6DC8CDE4202FA88D"
      cert_valid_from     = "2026-04-24"
      cert_valid_to       = "2027-04-24"

      country             = "DK"
      state               = "Midtjylland"
      locality            = "Hammel"
      email               = "???"
      rdn_serial_number   = "36932813"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "66:64:77:70:6e:04:5d:65:58:e9:13:66:a7:1b:28:03"
      )
}
