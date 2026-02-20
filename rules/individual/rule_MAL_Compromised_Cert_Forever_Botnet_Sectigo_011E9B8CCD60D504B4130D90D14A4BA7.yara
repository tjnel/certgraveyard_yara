import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_Sectigo_011E9B8CCD60D504B4130D90D14A4BA7 {
   meta:
      description         = "Detects Forever Botnet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-02"
      version             = "1.0"

      hash                = "dd1e7fd35306a22f511197716c7e9fe2c1ba149ffd275a5221c4452165a4b29d"
      malware             = "Forever Botnet"
      malware_type        = "Unknown"
      malware_notes       = "C2: kapa[.]is/f"

      signer              = "MAYDA PETROL OTOMOTIV INSAAT LIMITED SIRKETI"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "01:1e:9b:8c:cd:60:d5:04:b4:13:0d:90:d1:4a:4b:a7"
      cert_thumbprint     = "CD0EC5A42195775521CA6246C215DEB116CFE18C"
      cert_valid_from     = "2026-02-02"
      cert_valid_to       = "2027-02-02"

      country             = "TR"
      state               = "İstanbul"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "324489-5"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "01:1e:9b:8c:cd:60:d5:04:b4:13:0d:90:d1:4a:4b:a7"
      )
}
