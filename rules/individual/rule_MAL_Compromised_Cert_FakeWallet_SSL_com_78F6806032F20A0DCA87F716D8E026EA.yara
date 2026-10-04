import "pe"

rule MAL_Compromised_Cert_FakeWallet_SSL_com_78F6806032F20A0DCA87F716D8E026EA {
   meta:
      description         = "Detects FakeWallet with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-10"
      version             = "1.0"

      hash                = "f3a9a193102bb50ca22e2c86e5d13c931924aad3806833dee2e28257c83a4860"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = "Fake Mantle Wallet"

      signer              = "JACOB ADDOW"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "78:f6:80:60:32:f2:0a:0d:ca:87:f7:16:d8:e0:26:ea"
      cert_thumbprint     = "1dd2a9dd09c8372790c781515308df0181010c86"
      cert_valid_from     = "2026-09-10"
      cert_valid_to       = "2027-09-10"

      country             = "US"
      state               = "Massachusetts"
      locality            = "Worcester"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "78:f6:80:60:32:f2:0a:0d:ca:87:f7:16:d8:e0:26:ea"
      )
}
