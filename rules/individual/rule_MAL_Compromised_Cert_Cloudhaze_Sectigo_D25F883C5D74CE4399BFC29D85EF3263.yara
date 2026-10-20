import "pe"

rule MAL_Compromised_Cert_Cloudhaze_Sectigo_D25F883C5D74CE4399BFC29D85EF3263 {
   meta:
      description         = "Detects Cloudhaze with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-09"
      version             = "1.0"

      hash                = "7e71e072fbf39e4aaebad71c0e9e3443f9a4455faf687eb87264019cac342c31"
      malware             = "Cloudhaze"
      malware_type        = "Backdoor"
      malware_notes       = ""

      signer              = "Xiamen Jinduoduo Technology Consulting Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "d2:5f:88:3c:5d:74:ce:43:99:bf:c2:9d:85:ef:32:63"
      cert_thumbprint     = "5c0180432cdd93605d1ec2350a0f5b65978e2e22"
      cert_valid_from     = "2026-03-09"
      cert_valid_to       = "2027-03-09"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "d2:5f:88:3c:5d:74:ce:43:99:bf:c2:9d:85:ef:32:63"
      )
}
