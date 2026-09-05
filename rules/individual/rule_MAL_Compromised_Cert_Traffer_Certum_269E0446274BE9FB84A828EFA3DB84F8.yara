import "pe"

rule MAL_Compromised_Cert_Traffer_Certum_269E0446274BE9FB84A828EFA3DB84F8 {
   meta:
      description         = "Detects Traffer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-10"
      version             = "1.0"

      hash                = "3d02e5e1dedd63ec855b2d42869a5f891b0015e025b53d2fabd16be83deabba3"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = "Fake docusign"

      signer              = "CODE LOFTS d.o.o."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "26:9e:04:46:27:4b:e9:fb:84:a8:28:ef:a3:db:84:f8"
      cert_thumbprint     = "9f7b5c633187b88735a6a861b4730f9e16424045"
      cert_valid_from     = "2026-08-10"
      cert_valid_to       = "2027-08-10"

      country             = "HR"
      state               = "Splitsko-dalmatinska županija"
      locality            = "Split"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "26:9e:04:46:27:4b:e9:fb:84:a8:28:ef:a3:db:84:f8"
      )
}
