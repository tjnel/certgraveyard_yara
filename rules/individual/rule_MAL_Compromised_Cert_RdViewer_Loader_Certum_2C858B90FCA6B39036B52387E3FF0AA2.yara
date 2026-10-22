import "pe"

rule MAL_Compromised_Cert_RdViewer_Loader_Certum_2C858B90FCA6B39036B52387E3FF0AA2 {
   meta:
      description         = "Detects RdViewer Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-09"
      version             = "1.0"

      hash                = "e71149d889cc558e6328ea7ce3498cd858c26ab282cda9410ccc51f6275f7da6"
      malware             = "RdViewer Loader"
      malware_type        = "Remote access tool"
      malware_notes       = "C2: 1.14.146.76   https://rogueauthority.org/signed-disk-manager-installs-rdviewer-backdoor"

      signer              = "邓凯友"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "2c:85:8b:90:fc:a6:b3:90:36:b5:23:87:e3:ff:0a:a2"
      cert_thumbprint     = "b90539c313ea3ae0f0aff70f4729d17040e88327"
      cert_valid_from     = "2026-10-09"
      cert_valid_to       = "2027-10-09"

      country             = "CN"
      state               = "湖南省"
      locality            = "洪江市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "2c:85:8b:90:fc:a6:b3:90:36:b5:23:87:e3:ff:0a:a2"
      )
}
