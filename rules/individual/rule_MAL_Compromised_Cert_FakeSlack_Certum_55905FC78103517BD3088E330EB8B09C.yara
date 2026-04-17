import "pe"

rule MAL_Compromised_Cert_FakeSlack_Certum_55905FC78103517BD3088E330EB8B09C {
   meta:
      description         = "Detects FakeSlack with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-16"
      version             = "1.0"

      hash                = "20c2d8267013675ee535ad9a6721588790fe122a8b633e1d31c7cce6caf2292e"
      malware             = "FakeSlack"
      malware_type        = "Unknown"
      malware_notes       = "Fake Slack build fetching payloads from C2: 94.232.46.16"

      signer              = "Open Source Developer KOSTIANTΥΝ CHUDINOV"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "55:90:5f:c7:81:03:51:7b:d3:08:8e:33:0e:b8:b0:9c"
      cert_thumbprint     = "ABF8CEF6B261DDAC825A17A469FAAACA289A4115"
      cert_valid_from     = "2026-04-16"
      cert_valid_to       = "2027-04-16"

      country             = "UA"
      state               = "Vinnytsia Oblast"
      locality            = "Zhyhalivka"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "55:90:5f:c7:81:03:51:7b:d3:08:8e:33:0e:b8:b0:9c"
      )
}
