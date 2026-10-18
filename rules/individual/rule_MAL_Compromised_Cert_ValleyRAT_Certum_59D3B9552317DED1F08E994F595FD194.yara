import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_59D3B9552317DED1F08E994F595FD194 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-16"
      version             = "1.0"

      hash                = "f211eb4e9b7cfab20d5e4b747a8b4b5a1a1f4aade39621a559c5715ec4fcea86"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "海口市柳楠商贸有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "59:d3:b9:55:23:17:de:d1:f0:8e:99:4f:59:5f:d1:94"
      cert_thumbprint     = "6d7df3a5be1043ec3d29b557f60ac3c369c136d4"
      cert_valid_from     = "2026-03-16"
      cert_valid_to       = "2027-03-16"

      country             = "CN"
      state               = "海南"
      locality            = "海口"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "59:d3:b9:55:23:17:de:d1:f0:8e:99:4f:59:5f:d1:94"
      )
}
