import "pe"

rule MAL_Compromised_Cert_AsyncRAT_Certum_497BD0833E4FAC9607281612BB467077 {
   meta:
      description         = "Detects AsyncRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-19"
      version             = "1.0"

      hash                = "90d6c9046a654b22e8e6ece8b58bc76bc44bc37a4c7cc66b28f7ecad59859cb6"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "南京艮衡钧润科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "49:7b:d0:83:3e:4f:ac:96:07:28:16:12:bb:46:70:77"
      cert_thumbprint     = "2eaf3bdaff971330707026eb52b2d72d23430412"
      cert_valid_from     = "2026-05-19"
      cert_valid_to       = "2027-05-19"

      country             = "CN"
      state               = "江苏"
      locality            = "南京"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "49:7b:d0:83:3e:4f:ac:96:07:28:16:12:bb:46:70:77"
      )
}
