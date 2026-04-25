import "pe"

rule MAL_Compromised_Cert_RUS_53_Sectigo_009545C5CE89F001DB71C519825BB6E464 {
   meta:
      description         = "Detects RUS-53 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "bc8299142bcf0175ba531507b7149a87888fd87cbaacce491ea651662f033afc"
      malware             = "RUS-53"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "Suzhou Binfen Shuji Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:95:45:c5:ce:89:f0:01:db:71:c5:19:82:5b:b6:e4:64"
      cert_thumbprint     = "EB1DEC424BF325159C824CFDECC0EE7AD203A177"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2027-04-08"

      country             = "CN"
      state               = "Jiangsu Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91320594MA1R97095R"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:95:45:c5:ce:89:f0:01:db:71:c5:19:82:5b:b6:e4:64"
      )
}
