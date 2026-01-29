import "pe"

rule MAL_Compromised_Cert_LegionLoader_Certum_66245C8FEF6F0EF948111C458D177B9F {
   meta:
      description         = "Detects LegionLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-14"
      version             = "1.0"

      hash                = "7cc1c413cd12c8bc7f5811036c6ad662b07744cd8a466fa51e49d9988dfd3000"
      malware             = "LegionLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Doken Consult OU"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "66:24:5c:8f:ef:6f:0e:f9:48:11:1c:45:8d:17:7b:9f"
      cert_thumbprint     = "15537B0C69AAE110E9695A75E5A6480754CA1ADD"
      cert_valid_from     = "2024-05-14"
      cert_valid_to       = "2025-05-14"

      country             = "EE"
      state               = "???"
      locality            = "Tallinn"
      email               = "???"
      rdn_serial_number   = "14918730"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "66:24:5c:8f:ef:6f:0e:f9:48:11:1c:45:8d:17:7b:9f"
      )
}
