import "pe"

rule MAL_Compromised_Cert_FakeKeePass_Sectigo_00C7A713AF125FBE47B79DCB11EC819E16 {
   meta:
      description         = "Detects FakeKeePass with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-02"
      version             = "1.0"

      hash                = "fa68320fd6c7ea9849145066b7b13507cf4186900a218cdc67d387341632d825"
      malware             = "FakeKeePass"
      malware_type        = "Unknown"
      malware_notes       = "Malicious KeePass Installer. C2: 93.152.217.97"

      signer              = "Shenzhen Xingzhongxing Electronic Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:c7:a7:13:af:12:5f:be:47:b7:9d:cb:11:ec:81:9e:16"
      cert_thumbprint     = "718399A72C33F8CF13183193497365D043E58D76"
      cert_valid_from     = "2026-01-02"
      cert_valid_to       = "2027-01-02"

      country             = "CN"
      state               = "Guangdong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91440300MAD22F4T7A"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:c7:a7:13:af:12:5f:be:47:b7:9d:cb:11:ec:81:9e:16"
      )
}
