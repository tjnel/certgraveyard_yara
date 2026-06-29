import "pe"

rule MAL_Compromised_Cert_Gh0stRAT_Certum_7FDABB90421A3F81B7EA70A22C68E9FD {
   meta:
      description         = "Detects Gh0stRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-26"
      version             = "1.0"

      hash                = "7317d297686d154b4d78217e100df5f57949f05efe095f1a017b5988cddef98b"
      malware             = "Gh0stRAT"
      malware_type        = "Unknown"
      malware_notes       = "C2: 223.26.52.90"

      signer              = "Shanxi Tiandi Chunqiu Agricultural Development Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "7f:da:bb:90:42:1a:3f:81:b7:ea:70:a2:2c:68:e9:fd"
      cert_thumbprint     = "7ACBD8FA5C0064D8C66B0955ADD2BFDCE724C672"
      cert_valid_from     = "2026-05-26"
      cert_valid_to       = "2027-05-26"

      country             = "CN"
      state               = "山西"
      locality            = "运城"
      email               = "???"
      rdn_serial_number   = "91140829MA0GWC5HXQ"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "7f:da:bb:90:42:1a:3f:81:b7:ea:70:a2:2c:68:e9:fd"
      )
}
