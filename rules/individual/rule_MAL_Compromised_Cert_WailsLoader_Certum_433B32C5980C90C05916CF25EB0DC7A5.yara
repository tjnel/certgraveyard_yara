import "pe"

rule MAL_Compromised_Cert_WailsLoader_Certum_433B32C5980C90C05916CF25EB0DC7A5 {
   meta:
      description         = "Detects WailsLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-10"
      version             = "1.0"

      hash                = "a901bb05c72b20363a2f25ba12a2cc67eae0f6acf031d78a2f7f2de389ed84ff"
      malware             = "WailsLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "YOUR CHANCE j.d.o.o."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "43:3b:32:c5:98:0c:90:c0:59:16:cf:25:eb:0d:c7:a5"
      cert_thumbprint     = "980a6ccad38404410e319eed96ac32675bb8bfb3f558cbb06fa4c4cc563edb8c"
      cert_valid_from     = "2026-09-10"
      cert_valid_to       = "2027-09-10"

      country             = "HR"
      state               = "Grad Zagreb"
      locality            = "Zagreb"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "43:3b:32:c5:98:0c:90:c0:59:16:cf:25:eb:0d:c7:a5"
      )
}
