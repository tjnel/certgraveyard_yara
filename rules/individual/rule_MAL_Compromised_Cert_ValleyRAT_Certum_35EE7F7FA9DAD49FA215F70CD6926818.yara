import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_35EE7F7FA9DAD49FA215F70CD6926818 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-20"
      version             = "1.0"

      hash                = "985f74f534f9a5c9335d3a123876d359ea082f39ade959fb854c61ad8b7c7a84"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = "C2: nvidla[.]my"

      signer              = "Yuanjie Nong"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "35:ee:7f:7f:a9:da:d4:9f:a2:15:f7:0c:d6:92:68:18"
      cert_thumbprint     = "60d7e17a944e25aedd20d6d5a31fc03f938d01af"
      cert_valid_from     = "2026-04-20"
      cert_valid_to       = "2027-04-20"

      country             = "CN"
      state               = "Guangxi"
      locality            = "Ningming"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "35:ee:7f:7f:a9:da:d4:9f:a2:15:f7:0c:d6:92:68:18"
      )
}
