import "pe"

rule MAL_Compromised_Cert_TransferLoader_Sectigo_701640EA48E057540967509B99E48AE5 {
   meta:
      description         = "Detects TransferLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-11"
      version             = "1.0"

      hash                = "2c70e3b4af65679fc4f4c135dc1c03bd7ec2ae8065e2e5c50db3aaec0effc11f"
      malware             = "TransferLoader"
      malware_type        = "Loader"
      malware_notes       = "Malware requires a specific file name to run. Reaches out to mstiserviceconfig[.]com"

      signer              = "Hangzhou Wenyu Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "70:16:40:ea:48:e0:57:54:09:67:50:9b:99:e4:8a:e5"
      cert_thumbprint     = "D1F7153FE825467A3069D70F8A2493CB4E18B758"
      cert_valid_from     = "2025-12-11"
      cert_valid_to       = "2026-12-11"

      country             = "CN"
      state               = "Zhejiang Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91330114MA2KLTYM9M"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "70:16:40:ea:48:e0:57:54:09:67:50:9b:99:e4:8a:e5"
      )
}
