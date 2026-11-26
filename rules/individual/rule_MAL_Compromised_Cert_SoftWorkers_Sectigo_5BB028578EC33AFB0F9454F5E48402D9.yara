import "pe"

rule MAL_Compromised_Cert_SoftWorkers_Sectigo_5BB028578EC33AFB0F9454F5E48402D9 {
   meta:
      description         = "Detects SoftWorkers with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-28"
      version             = "1.0"

      hash                = "9c242f456a2f12306f53e55d5b4c7dd5e413c899559646aad5b0346b82547175"
      malware             = "SoftWorkers"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SIA JOBCENTER"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "5b:b0:28:57:8e:c3:3a:fb:0f:94:54:f5:e4:84:02:d9"
      cert_thumbprint     = "92795fc876279fc2dba707ae8110bf2d3304b33c"
      cert_valid_from     = "2026-04-28"
      cert_valid_to       = "2027-04-28"

      country             = "LV"
      state               = "Rīga"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "5b:b0:28:57:8e:c3:3a:fb:0f:94:54:f5:e4:84:02:d9"
      )
}
