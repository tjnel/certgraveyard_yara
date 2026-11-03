import "pe"

rule MAL_Compromised_Cert_Traffer_Sectigo_9A08C56B2270D3359DBACAE4A9F47E02 {
   meta:
      description         = "Detects Traffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-20"
      version             = "1.0"

      hash                = "e5634f9e2668fffdaffe257bbe4d8eee07c02fb9435fe82c753387f544f87cf0"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CODE LOFTS d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "9a:08:c5:6b:22:70:d3:35:9d:ba:ca:e4:a9:f4:7e:02"
      cert_thumbprint     = "f84036806715099004b1f59802b78c2a97162ec1"
      cert_valid_from     = "2026-07-20"
      cert_valid_to       = "2027-07-20"

      country             = "HR"
      state               = "Splitsko-dalmatinska županija"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "9a:08:c5:6b:22:70:d3:35:9d:ba:ca:e4:a9:f4:7e:02"
      )
}
