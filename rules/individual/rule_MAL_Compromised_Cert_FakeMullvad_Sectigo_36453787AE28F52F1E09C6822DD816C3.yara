import "pe"

rule MAL_Compromised_Cert_FakeMullvad_Sectigo_36453787AE28F52F1E09C6822DD816C3 {
   meta:
      description         = "Detects FakeMullvad with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-02"
      version             = "1.0"

      hash                = "a4b6e81233ca2b8a4c6ace3da6344a7e0a8df92ee06c4763c7b18001c169b133"
      malware             = "FakeMullvad"
      malware_type        = "Loader"
      malware_notes       = "Fake Mullvad VPN Installer. C2: 93.152.217.97"

      signer              = "Xiamen Quanlian Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "36:45:37:87:ae:28:f5:2f:1e:09:c6:82:2d:d8:16:c3"
      cert_thumbprint     = "7055210760DA2A80BD7048B7EDCA12812CD18ED3"
      cert_valid_from     = "2026-01-02"
      cert_valid_to       = "2027-01-02"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "913502030658786582"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "36:45:37:87:ae:28:f5:2f:1e:09:c6:82:2d:d8:16:c3"
      )
}
