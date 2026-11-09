import "pe"

rule MAL_Compromised_Cert_RdViewer_Certum_23FF0D00EE80E58892220C95AE8EA33B {
   meta:
      description         = "Detects RdViewer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-02"
      version             = "1.0"

      hash                = "06fc08506f84d43bc1ede3a4c152dd9a6646e65c9901f72d79c7c4d7a834db19"
      malware             = "RdViewer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "安云鹏"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "23:ff:0d:00:ee:80:e5:88:92:22:0c:95:ae:8e:a3:3b"
      cert_thumbprint     = "f10ad5627a33cd3b5a3d81a3721f1cab9db62b5d"
      cert_valid_from     = "2026-11-02"
      cert_valid_to       = "2027-11-02"

      country             = "CN"
      state               = "安徽省"
      locality            = "六安市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "23:ff:0d:00:ee:80:e5:88:92:22:0c:95:ae:8e:a3:3b"
      )
}
